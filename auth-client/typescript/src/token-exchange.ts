import { createHash, randomUUID, sign } from "node:crypto";

import { DEFAULT_TIMEOUT_MS, requestTimeout } from "./timeout.js";

const EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DEFAULT_CACHE_ENTRIES = 128;
const DEFAULT_EXPIRY_MARGIN_MS = 30_000;

function encode(value: object): string { return Buffer.from(JSON.stringify(value)).toString("base64url"); }

function exchangeCacheKey(
  subjectToken: string, audience: string, scopes: readonly string[], requestedType = ACCESS_TOKEN_TYPE,
): string {
  const material = `${subjectToken}\0${audience}\0${scopes.join(" ")}`;
  return createHash("sha256").update(requestedType === ACCESS_TOKEN_TYPE ? material : `${material}\0${requestedType}`).digest("hex");
}

/**
 * Thrown when the token endpoint answers a token exchange with a non-2xx status.
 * It carries only the status, never the response body.
 */
export class ExchangeError extends Error {
  constructor(readonly status: number) {
    super(`token exchange returned HTTP ${status}`);
    this.name = "ExchangeError";
  }
}

export class PrivateKeyJWTClientAuth {
  constructor(
    readonly clientId: string,
    private readonly privateKey: string,
    readonly keyId: string,
    readonly audience?: string,
  ) {}

  assertion(tokenEndpoint: string, now = Math.floor(Date.now() / 1000)): string {
    const message = `${encode({ typ: "JWT", alg: "RS256", kid: this.keyId })}.${encode({
      iss: this.clientId, sub: this.clientId, aud: this.audience ?? tokenEndpoint,
      iat: now, exp: now + 300, jti: randomUUID(),
    })}`;
    return `${message}.${sign("RSA-SHA256", Buffer.from(message), this.privateKey).toString("base64url")}`;
  }
}

export interface ExchangedToken {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  audience: string;
  scopes: ReadonlySet<string>;
}

export class TokenExchangeCache {
  private readonly values = new Map<string, ExchangedToken>();

  constructor(
    readonly maxEntries = DEFAULT_CACHE_ENTRIES,
    private readonly expiryMarginMs = DEFAULT_EXPIRY_MARGIN_MS,
  ) {
    if (maxEntries < 1) throw new Error("maxEntries must be positive");
    if (expiryMarginMs < 0) throw new Error("expiryMarginMs must be non-negative");
  }

  get size(): number { return this.values.size; }

  get(key: string, now = Date.now()): ExchangedToken | undefined {
    const value = this.values.get(key);
    if (!value) return undefined;
    if (value.expiresAt <= now + this.expiryMarginMs) {
      this.values.delete(key);
      return undefined;
    }
    this.values.delete(key);
    this.values.set(key, value);
    return value;
  }

  set(key: string, value: ExchangedToken): void {
    if (this.values.has(key)) this.values.delete(key);
    this.values.set(key, value);
    while (this.values.size > this.maxEntries) {
      const oldest = this.values.keys().next().value;
      if (oldest !== undefined) this.values.delete(oldest);
    }
  }
}

export interface TokenExchangeClientOptions {
  endpoint: string;
  clientAuth?: PrivateKeyJWTClientAuth;
  fetch?: typeof globalThis.fetch;
  allowInsecure?: boolean;
  timeoutMs?: number;
  /** Pass `null` to disable caching, so every call is authorised afresh (for example to honour session revocation). */
  cache?: TokenExchangeCache | null;
  /** Defaults to the RFC 8693 access-token type. Set it to request another issued type, such as a credential-access assertion. */
  requestedTokenType?: string;
}

export class TokenExchangeClient {
  private readonly fetcher: typeof globalThis.fetch;
  private readonly cache: TokenExchangeCache | null;
  private readonly requestedTokenType: string;
  private readonly timeoutMs: number;

  constructor(private readonly options: TokenExchangeClientOptions) {
    let url: URL;
    try {
      url = new URL(options.endpoint);
    } catch {
      throw new Error("token endpoint must be an absolute URL");
    }
    if (url.protocol !== "https:" && options.allowInsecure !== true) {
      throw new Error("token endpoint must use https");
    }
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.cache = options.cache === undefined ? new TokenExchangeCache() : options.cache;
    this.requestedTokenType = options.requestedTokenType ?? ACCESS_TOKEN_TYPE;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async exchange(
    subjectToken: string,
    audience: string,
    scopes: Iterable<string> = [],
    signal?: AbortSignal,
  ): Promise<ExchangedToken> {
    const sortedScopes = [...scopes].sort();
    const key = exchangeCacheKey(subjectToken, audience, sortedScopes, this.requestedTokenType);
    const cached = this.cache?.get(key);
    if (cached) return cached;
    const form = new URLSearchParams({
      grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
      requested_token_type: this.requestedTokenType, audience, scope: sortedScopes.join(" "),
    });
    if (this.options.clientAuth) {
      form.set("client_id", this.options.clientAuth.clientId);
      form.set("client_assertion_type", ASSERTION_TYPE);
      form.set("client_assertion", this.options.clientAuth.assertion(this.options.endpoint));
    }
    const init: RequestInit = {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form,
      // 307 and 308 replay the body, so a redirect from an https endpoint to an
      // http one would resend the subject token and client assertion in
      // cleartext and bypass the scheme check above.
      redirect: "error",
    };
    const { signal: requestSignal, release } = requestTimeout(this.timeoutMs, signal);
    if (requestSignal) init.signal = requestSignal;
    try {
      const response = await this.fetcher(this.options.endpoint, init);
      if (!response.ok) throw new ExchangeError(response.status);
      const data = await response.json() as Record<string, unknown>;
      if (typeof data.access_token !== "string") throw new Error("token exchange response has no access_token");
      const expiresIn = typeof data.expires_in === "number" && data.expires_in > 0 ? data.expires_in : 300;
      const token: ExchangedToken = {
        accessToken: data.access_token,
        tokenType: typeof data.token_type === "string" ? data.token_type : "Bearer",
        expiresAt: Date.now() + expiresIn * 1000,
        audience,
        scopes: new Set(typeof data.scope === "string" ? data.scope.split(/\s+/).filter(Boolean) : []),
      };
      this.cache?.set(key, token);
      return token;
    } finally {
      release();
    }
  }

}
