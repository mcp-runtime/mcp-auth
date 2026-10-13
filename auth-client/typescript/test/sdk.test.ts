import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  AuthenticationError,
  ExchangeError,
  JWTVerifier,
  TokenExchangeCache,
  TokenExchangeClient,
  TokenVerificationError,
  authenticateRequest,
  bearerChallenge,
  protectedResourceMetadata,
} from "../src/index.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = publicKey.export({ format: "jwk" });
const issuer = "https://auth.example.com";
const audience = "https://mcp.example.com/mcp";

function jwt(overrides: Record<string, unknown> = {}, headerOverrides: Record<string, unknown> = {}): string {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({ alg: "RS256", typ: "at+jwt", kid: "test-key", ...headerOverrides });
  const claims = encode({
    iss: issuer, aud: audience, sub: "user-123", scope: "tools:read profile",
    exp: Math.floor(Date.now() / 1000) + 300, ...overrides,
  });
  const message = `${header}.${claims}`;
  return `${message}.${sign("RSA-SHA256", Buffer.from(message), privateKey).toString("base64url")}`;
}

function verifier(requiredScopes = ["tools:read"]): JWTVerifier {
  return new JWTVerifier({
    jwksUri: `${issuer}/.well-known/jwks.json`, issuer, audience, requiredScopes,
    fetch: async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] })),
  });
}

test("verifies signature, issuer, audience, subject, expiry, and scopes", async () => {
  const claims = await verifier().verify(jwt());
  assert.equal(claims.subject, "user-123");
  assert.deepEqual([...claims.scopes], ["tools:read", "profile"]);
  await assert.rejects(verifier().verify(jwt({ aud: "https://other.example.com" })), /audience/);
  await assert.rejects(verifier().verify(jwt({ exp: 1 })), /expired/);
  await assert.rejects(verifier(["tools:write"]).verify(jwt()), /required scopes/);
});

test("authenticates Node requests and distinguishes missing scope", async () => {
  const claims = await authenticateRequest({ headers: { authorization: `Bearer ${jwt()}` } }, verifier());
  assert.equal(claims.subject, "user-123");
  await assert.rejects(
    authenticateRequest({ headers: { authorization: `Bearer ${jwt()}` } }, verifier(["tools:write"])),
    (error: unknown) => error instanceof AuthenticationError && error.status === 403,
  );
});

test("derives stable metadata and escapes bearer challenges", () => {
  assert.deepEqual(protectedResourceMetadata(verifier(["tools:write", "tools:read"]), audience, issuer), {
    resource: audience,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: ["tools:read", "tools:write"],
  });
  assert.equal(bearerChallenge("https://example.com/\"metadata"), 'Bearer resource_metadata="https://example.com/\\"metadata"');
});

test("exchanges and caches a downstream token", async () => {
  let calls = 0;
  const client = new TokenExchangeClient({
    endpoint: `${issuer}/token`,
    fetch: async (_input, init) => {
      calls++;
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get("grant_type"), "urn:ietf:params:oauth:grant-type:token-exchange");
      assert.equal(body.get("audience"), "https://api.example.com");
      return new Response(JSON.stringify({ access_token: "downstream", expires_in: 300, scope: "read" }));
    },
  });
  const first = await client.exchange("subject-token", "https://api.example.com", ["read"]);
  const second = await client.exchange("subject-token", "https://api.example.com", ["read"]);
  assert.equal(first.accessToken, "downstream");
  assert.equal(second, first);
  assert.equal(calls, 1);
});

test("token endpoint requires https unless allowInsecure is set", async () => {
  assert.throws(() => new TokenExchangeClient({ endpoint: "http://127.0.0.1/token" }), /https/);
  const client = new TokenExchangeClient({
    endpoint: "http://127.0.0.1/token",
    allowInsecure: true,
    fetch: async () => new Response(JSON.stringify({ access_token: "downstream", expires_in: 300 })),
  });
  assert.equal((await client.exchange("subject-token", "https://api.example.com")).accessToken, "downstream");
});

test("exchange cache is a bounded LRU and deletes expired entries on read", () => {
  const cache = new TokenExchangeCache(2, 30_000);
  const fresh = (accessToken: string) => ({
    accessToken, tokenType: "Bearer", expiresAt: Date.now() + 60_000, audience: "https://api.example.com", scopes: new Set<string>(),
  });
  cache.set("a", fresh("a"));
  cache.set("b", fresh("b"));
  cache.set("c", fresh("c"));
  assert.equal(cache.size, 2);
  assert.equal(cache.get("a"), undefined);
  assert.equal(cache.get("c")?.accessToken, "c");
  const expiring = new TokenExchangeCache(2, 30_000);
  expiring.set("kept", fresh("kept"));
  expiring.set("stale", {
    accessToken: "stale", tokenType: "Bearer", expiresAt: Date.now(), audience: "https://api.example.com", scopes: new Set<string>(),
  });
  assert.equal(expiring.get("stale"), undefined);
  assert.equal(expiring.size, 1);
  assert.equal(expiring.get("kept")?.accessToken, "kept");
});

test("scope order does not miss the exchange cache", async () => {
  let calls = 0;
  const client = new TokenExchangeClient({
    endpoint: `${issuer}/token`,
    fetch: async () => {
      calls++;
      return new Response(JSON.stringify({ access_token: "downstream", expires_in: 300 }));
    },
  });
  await client.exchange("subject-token", "https://api.example.com", ["b", "a"]);
  await client.exchange("subject-token", "https://api.example.com", ["a", "b"]);
  assert.equal(calls, 1);
});

test("outbound calls time out by default", async () => {
  const hung: typeof fetch = (_input, init) => new Promise<Response>((_resolve, reject) => {
    const signal = init?.signal;
    if (!signal) return;
    const fail = () => reject(signal.reason instanceof Error ? signal.reason : new Error("aborted"));
    if (signal.aborted) fail();
    else signal.addEventListener("abort", fail, { once: true });
  });
  const exchange = new TokenExchangeClient({ endpoint: `${issuer}/token`, timeoutMs: 20, fetch: hung });
  await assert.rejects(exchange.exchange("subject-token", "https://api.example.com"));
  const verifier = new JWTVerifier({
    jwksUri: `${issuer}/.well-known/jwks.json`, issuer, audience, timeoutMs: 20, fetch: hung,
  });
  await assert.rejects(
    verifier.verify(jwt()),
    (error: unknown) => error instanceof TokenVerificationError && /abort|timeout/i.test(String(error.cause)),
  );
});

test("unknown kid does not refetch JWKS", async () => {
  let calls = 0;
  const client = new JWTVerifier({
    jwksUri: `${issuer}/.well-known/jwks.json`, issuer, audience,
    fetch: async () => {
      calls++;
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] }));
    },
  });
  const token = jwt({}, { kid: "missing" });
  for (let attempt = 0; attempt < 5; attempt += 1) await assert.rejects(client.verify(token));
  assert.equal(calls, 1);
});

test("forced JWKS refresh is not satisfied by an older in-flight fetch", async () => {
  let calls = 0;
  let releaseSecond: () => void = () => {};
  const gate = new Promise<void>((resolve) => { releaseSecond = resolve; });
  const keyA = { ...jwk, kid: "a", alg: "RS256", kty: "RSA" };
  const keyB = { ...jwk, kid: "b", alg: "RS256", kty: "RSA" };
  const client = new JWTVerifier({
    jwksUri: `${issuer}/.well-known/jwks.json`, issuer, audience,
    jwksTtlMs: 0,
    jwksMinFetchMs: 0,
    fetch: async () => {
      calls += 1;
      if (calls === 1) return new Response(JSON.stringify({ keys: [keyA] }));
      if (calls === 2) {
        await gate;
        return new Response(JSON.stringify({ keys: [keyA] }));
      }
      return new Response(JSON.stringify({ keys: [keyA, keyB] }));
    },
  });
  await client.verify(jwt({}, { kid: "a" }));
  const pendingKnown = client.verify(jwt({}, { kid: "a" }));
  for (let attempt = 0; attempt < 50 && calls < 2; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const pendingRotated = client.verify(jwt({}, { kid: "b" }));
  releaseSecond();
  await pendingKnown;
  await pendingRotated;
  assert.equal(calls, 3);
});

test("unique unknown kids share the global JWKS refresh interval", async () => {
  // Keying the interval on repeated misses of one kid let a caller send a
  // stream of distinct kids and draw one JWKS request per token.
  let calls = 0;
  const client = new JWTVerifier({
    jwksUri: `${issuer}/.well-known/jwks.json`, issuer, audience,
    fetch: async () => {
      calls++;
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] }));
    },
  });
  for (let attempt = 0; attempt < 10; attempt += 1) {
    await assert.rejects(client.verify(jwt({}, { kid: `unique-${attempt}` })));
  }
  assert.equal(calls, 1);
});

test("exchange refuses redirects so a 307 cannot resend the body over http", async () => {
  let seen: RequestInit | undefined;
  const client = new TokenExchangeClient({
    endpoint: `${issuer}/token`,
    fetch: async (_input, init) => {
      seen = init;
      return new Response(JSON.stringify({ access_token: "downstream", expires_in: 300 }));
    },
  });
  await client.exchange("subject-token", "https://api.example.com");
  assert.equal(seen?.redirect, "error");
});

test("requestedTokenType is sent, cached separately, and can bypass the cache", async () => {
  const assertionType = "urn:mcp-auth:token-type:credential-access-assertion";
  const requested: (string | null)[] = [];
  const fetcher = async (_input: unknown, init?: RequestInit) => {
    requested.push(new URLSearchParams(String(init?.body)).get("requested_token_type"));
    return new Response(JSON.stringify({ access_token: "assertion", token_type: "N_A", expires_in: 60 }));
  };
  const cached = new TokenExchangeClient({ endpoint: `${issuer}/token`, fetch: fetcher, requestedTokenType: assertionType });
  assert.equal((await cached.exchange("subject", "https://mcp.example.com/mcp")).tokenType, "N_A");
  await cached.exchange("subject", "https://mcp.example.com/mcp");
  assert.deepEqual(requested, [assertionType]);

  const fresh = new TokenExchangeClient({ endpoint: `${issuer}/token`, fetch: fetcher, requestedTokenType: assertionType, cache: null });
  await fresh.exchange("subject", "https://mcp.example.com/mcp");
  await fresh.exchange("subject", "https://mcp.example.com/mcp");
  assert.equal(requested.length, 3);
});

test("a failed exchange throws ExchangeError with only the status", async () => {
  const client = new TokenExchangeClient({
    endpoint: `${issuer}/token`,
    fetch: async () => new Response(JSON.stringify({ error: "insufficient_scope", secret: "do-not-leak" }), { status: 403 }),
  });
  await assert.rejects(client.exchange("subject", "https://mcp.example.com/mcp"), (error: unknown) => {
    assert.ok(error instanceof ExchangeError);
    assert.equal(error.status, 403);
    assert.ok(!String(error.message).includes("do-not-leak"));
    return true;
  });
});

test("tokenTypes and requireType gate the JOSE typ header", async () => {
  const make = (options: Record<string, unknown> = {}) => new JWTVerifier({
    jwksUri: `${issuer}/.well-known/jwks.json`, issuer, audience,
    fetch: async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: "test-key" }] })), ...options,
  });
  const assertion = jwt({}, { typ: "credential-access+jwt" });
  await assert.rejects(make().verify(assertion), TokenVerificationError);
  assert.equal((await make({ tokenTypes: ["credential-access+jwt"], requireType: true }).verify(assertion)).subject, "user-123");
  await assert.rejects(make({ tokenTypes: ["credential-access+jwt"] }).verify(jwt()), TokenVerificationError);
  const untyped = jwt({}, { typ: undefined });
  await assert.rejects(make({ tokenTypes: ["credential-access+jwt"], requireType: true }).verify(untyped), TokenVerificationError);
  assert.equal((await make().verify(untyped)).subject, "user-123");
  assert.throws(() => make({ tokenTypes: [] }), /allowlisted/);
});
