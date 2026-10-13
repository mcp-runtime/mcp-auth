import { createPublicKey, verify as verifySignature, type JsonWebKey } from "node:crypto";
import { isIP } from "node:net";

import { DEFAULT_TIMEOUT_MS, requestTimeout } from "./timeout.js";

const MAX_JWKS_BYTES = 1024 * 1024;
const DEFAULT_JWKS_MIN_FETCH_MS = 30_000;
const DEFAULT_UNKNOWN_KEY_TTL_MS = 30_000;

export class TokenVerificationError extends Error {
  constructor(message = "invalid MCP access token", options?: ErrorOptions) {
    super(message, options);
    this.name = "TokenVerificationError";
  }
}

export interface TokenClaims {
  subject: string;
  issuer: string;
  audience: string[];
  scopes: ReadonlySet<string>;
  claims: Readonly<Record<string, unknown>>;
}

export interface JWTVerifierOptions {
  jwksUri: string;
  issuer: string;
  audience: string;
  requiredScopes?: Iterable<string>;
  fetch?: typeof globalThis.fetch;
  jwksTtlMs?: number;
  clockSkewSeconds?: number;
  ssrfSafe?: boolean;
  timeoutMs?: number;
  jwksMinFetchMs?: number;
  unknownKeyTtlMs?: number;
  /** Accepted JOSE `typ` values. Defaults to "JWT" and "at+jwt". */
  tokenTypes?: readonly string[];
  /** Reject tokens that carry no `typ`, so a verifier for a non-access token type cannot be satisfied by an untyped JWT. */
  requireType?: boolean;
}

interface JWKSDocument { keys: JsonWebKey[] }

function decodePart(value: string): Record<string, unknown> {
  try {
    const decoded: unknown = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error();
    return decoded as Record<string, unknown>;
  } catch (error) {
    throw new TokenVerificationError("JWT contains invalid JSON", { cause: error });
  }
}

function audiences(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return value;
  return [];
}

export class JWTVerifier {
  readonly jwksUri: string;
  readonly issuer: string;
  readonly audience: string;
  readonly requiredScopes: ReadonlySet<string>;
  private readonly tokenTypes: readonly string[];
  private readonly requireType: boolean;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly jwksTtlMs: number;
  private readonly clockSkewSeconds: number;
  private readonly ssrfSafe: boolean;
  private readonly timeoutMs: number;
  private readonly jwksMinFetchMs: number;
  private readonly unknownKeyTtlMs: number;
  private keys = new Map<string, JsonWebKey>();
  private loadedAt = 0;
  private lastRefresh = 0;
  private readonly unknownKids = new Map<string, number>();
  private loading: Promise<void> | undefined;

  constructor(options: JWTVerifierOptions) {
    this.tokenTypes = options.tokenTypes ?? ["JWT", "at+jwt"];
    if (this.tokenTypes.length === 0) throw new Error("at least one JWT type must be allowlisted");
    this.requireType = options.requireType ?? false;
    this.jwksUri = options.jwksUri;
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.requiredScopes = new Set(options.requiredScopes ?? []);
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.jwksTtlMs = options.jwksTtlMs ?? 300_000;
    this.clockSkewSeconds = options.clockSkewSeconds ?? 60;
    this.ssrfSafe = options.ssrfSafe ?? true;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.jwksMinFetchMs = options.jwksMinFetchMs ?? DEFAULT_JWKS_MIN_FETCH_MS;
    this.unknownKeyTtlMs = options.unknownKeyTtlMs ?? DEFAULT_UNKNOWN_KEY_TTL_MS;
  }

  async verify(token: string, signal?: AbortSignal): Promise<TokenClaims> {
    const parts = token.split(".");
    if (parts.length !== 3) throw new TokenVerificationError();
    const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
    const header = decodePart(encodedHeader);
    const claims = decodePart(encodedPayload);
    if (header.alg !== "RS256") throw new TokenVerificationError("JWT algorithm is not allowed");
    if (header.typ === undefined && this.requireType) throw new TokenVerificationError("JWT type is missing");
    if (header.typ !== undefined && (typeof header.typ !== "string" || !this.tokenTypes.includes(header.typ))) {
      throw new TokenVerificationError("JWT type is not allowed");
    }
    if (typeof header.kid !== "string" || !header.kid) throw new TokenVerificationError("JWT kid is missing");

    const jwk = await this.signingKey(header.kid, signal);
    if (!jwk) throw new TokenVerificationError("JWT signing key was not found");
    let validSignature = false;
    try {
      validSignature = verifySignature(
        "RSA-SHA256",
        Buffer.from(`${encodedHeader}.${encodedPayload}`),
        createPublicKey({ key: jwk, format: "jwk" }),
        Buffer.from(encodedSignature, "base64url"),
      );
    } catch (error) {
      throw new TokenVerificationError("JWT signing key is invalid", { cause: error });
    }
    if (!validSignature) throw new TokenVerificationError("JWT signature is invalid");

    const now = Date.now() / 1000;
    if (claims.iss !== this.issuer) throw new TokenVerificationError("JWT issuer is invalid");
    if (typeof claims.exp !== "number" || now > claims.exp + this.clockSkewSeconds) {
      throw new TokenVerificationError("JWT is expired");
    }
    if (typeof claims.nbf === "number" && now + this.clockSkewSeconds < claims.nbf) {
      throw new TokenVerificationError("JWT is not active");
    }
    const tokenAudiences = audiences(claims.aud);
    if (!tokenAudiences.includes(this.audience)) throw new TokenVerificationError("JWT audience is invalid");
    if (typeof claims.sub !== "string" || !claims.sub) throw new TokenVerificationError("JWT subject is missing");
    const scopes = new Set(typeof claims.scope === "string" ? claims.scope.split(/\s+/).filter(Boolean) : []);
    for (const scope of this.requiredScopes) {
      if (!scopes.has(scope)) throw new TokenVerificationError("JWT does not contain all required scopes");
    }
    return { subject: claims.sub, issuer: this.issuer, audience: tokenAudiences, scopes, claims };
  }

  private fresh(): boolean {
    return this.keys.size > 0 && Date.now() - this.loadedAt < this.jwksTtlMs;
  }

  // throttled reports whether a refresh happened too recently to allow
  // another. A cached key is still returned by signingKey when it holds one,
  // so throttling never rejects a token the current document can verify.
  private throttled(): boolean {
    return this.lastRefresh > 0 && Date.now() - this.lastRefresh < this.jwksMinFetchMs;
  }

  private recentMiss(kid: string): boolean {
    const missedAt = this.unknownKids.get(kid);
    if (missedAt === undefined) return false;
    const now = Date.now();
    return now - missedAt < this.unknownKeyTtlMs && now - this.lastRefresh < this.jwksMinFetchMs;
  }

  private async signingKey(kid: string, signal?: AbortSignal): Promise<JsonWebKey | undefined> {
    const cached = this.keys.get(kid);
    if (cached && this.fresh()) return cached;
    if (this.recentMiss(kid)) return undefined;
    // The refresh interval is global, not per kid. Keying it on repeated
    // misses of the same kid let an unauthenticated caller send a stream of
    // unique kids and draw one JWKS request per token.
    if (this.throttled()) return cached;
    // A kid that is absent from a populated cache needs its own fetch. Joining
    // an ordinary load that is already in flight would observe a document that
    // was requested before this kid was known.
    const force = this.keys.size > 0 && !this.keys.has(kid);
    await this.load(signal, force);
    const found = this.keys.get(kid);
    if (found) this.unknownKids.delete(kid);
    else this.unknownKids.set(kid, Date.now());
    return found;
  }

  private async load(signal: AbortSignal | undefined, force: boolean): Promise<void> {
    if (this.loading) {
      const inflight = this.loading;
      await inflight;
      if (!force) return;
      if (this.loading) return this.loading;
    }
    if (this.loading) return this.loading;
    const { signal: requestSignal, release } = requestTimeout(this.timeoutMs, signal);
    let pending: Promise<void>;
    pending = this.fetchJwks(requestSignal).finally(() => {
      release();
      if (this.loading === pending) this.loading = undefined;
    });
    this.loading = pending;
    return pending;
  }


  private async fetchJwks(signal?: AbortSignal): Promise<void> {
    this.validateJwksUri();
    try {
      const init: RequestInit = { headers: { accept: "application/json" }, redirect: "error" };
      if (signal) init.signal = signal;
      const response = await this.fetcher(this.jwksUri, init);
      if (!response.ok) throw new Error(`JWKS returned HTTP ${response.status}`);
      const text = await response.text();
      if (Buffer.byteLength(text) > MAX_JWKS_BYTES) throw new Error("JWKS response is too large");
      const document: unknown = JSON.parse(text);
      if (!document || typeof document !== "object" || !Array.isArray((document as JWKSDocument).keys)) {
        throw new Error("JWKS response is invalid");
      }
      const next = new Map<string, JsonWebKey>();
      for (const key of (document as JWKSDocument).keys) {
        if (key.kty === "RSA" && typeof key.kid === "string") next.set(key.kid, key);
      }
      this.keys = next;
      const now = Date.now();
      this.loadedAt = now;
      this.lastRefresh = now;
    } catch (error) {
      throw new TokenVerificationError("unable to load JWKS", { cause: error });
    }
  }

  private validateJwksUri(): void {
    let url: URL;
    try { url = new URL(this.jwksUri); } catch { throw new TokenVerificationError("JWKS URI must be absolute"); }
    if (!['http:', 'https:'].includes(url.protocol)) throw new TokenVerificationError("JWKS URI must use HTTP(S)");
    if (!this.ssrfSafe) return;
    if (url.username || url.password) throw new TokenVerificationError("JWKS URI must not contain credentials");
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !loopback) throw new TokenVerificationError("JWKS URI must use HTTPS");
    if (isIP(url.hostname.replace(/^\[|\]$/g, "")) && !loopback) {
      throw new TokenVerificationError("JWKS URI must not use a non-loopback IP address");
    }
  }
}
