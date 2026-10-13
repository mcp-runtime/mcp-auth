package server

import (
	"context"
	"time"
)

// KeyProvider is the production boundary for signing and public-key publication.
// A KMS/HSM or secret-manager adapter can implement it without changing handlers.
type KeyProvider interface {
	Sign(context.Context, string, string, string, []string, time.Duration, string) (string, error)
	JWKS(context.Context) (map[string]any, error)
	// Verify checks a token this provider previously signed and returns its
	// claims, so callers can confirm a bearer value actually originated here
	// before trusting it (e.g. as a token-exchange subject_token).
	Verify(context.Context, string) (map[string]any, error)
}

type LocalKeyProvider struct{ Keys *KeyManager }

func (p LocalKeyProvider) Sign(_ context.Context, issuer, subject, resource string, scopes []string, ttl time.Duration, nonce string) (string, error) {
	return p.Keys.Sign(issuer, subject, resource, scopes, ttl, nonce)
}

func (p LocalKeyProvider) JWKS(_ context.Context) (map[string]any, error) { return p.Keys.JWKS(), nil }

func (p LocalKeyProvider) Verify(_ context.Context, token string) (map[string]any, error) {
	return p.Keys.Verify(token)
}

// SessionSigner is an optional KeyProvider extension that stamps the login
// session id ("sid", the refresh-token family) into access tokens. Providers
// that do not implement it keep issuing tokens without sid; the KeyProvider
// signature is unchanged.
type SessionSigner interface {
	SignWithSession(ctx context.Context, issuer, subject, resource string, scopes []string, ttl time.Duration, nonce, sid string) (string, error)
}

// ClaimsSigner is an optional KeyProvider extension for signing server-issued
// JWTs other than access tokens, such as credential-access assertions.
type ClaimsSigner interface {
	SignClaims(ctx context.Context, typ string, claims map[string]any) (string, error)
}

func (p LocalKeyProvider) SignWithSession(_ context.Context, issuer, subject, resource string, scopes []string, ttl time.Duration, nonce, sid string) (string, error) {
	return p.Keys.SignWithSession(issuer, subject, resource, scopes, ttl, nonce, sid)
}

func (p LocalKeyProvider) SignClaims(_ context.Context, typ string, claims map[string]any) (string, error) {
	return p.Keys.SignClaims(typ, claims)
}
