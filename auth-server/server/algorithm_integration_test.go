package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signES256(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	headEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(header))
	claimEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	signingInput := headEncoded + "." + claimEncoded
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestClientAssertionSupportsES256(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := instance.Store.SaveClient(Client{ID: "es256-resource-server", Resource: instance.Config.Resources[0], TokenEndpointAuth: "private_key_jwt", PublicKeyPEM: string(publicPEM), Algorithm: "ES256"}); err != nil {
		t.Fatal(err)
	}

	subjectToken, err := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "user-1", instance.Config.Resources[0], []string{"tools:read"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	assertion := signES256(t, key,
		map[string]any{"typ": "JWT", "alg": "ES256"},
		map[string]any{"iss": "es256-resource-server", "sub": "es256-resource-server", "aud": instance.Config.Issuer + "/token", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": randomID()},
	)
	form := exchangeForm(subjectToken, "es256-resource-server", assertion)

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected an ES256 client assertion to authenticate, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestOIDCVerifyIDTokenSupportsAllowedES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "EC", "crv": "P-256", "kid": "ec-key",
			"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}}})
	}))
	defer jwksServer.Close()

	const issuer = "https://es256-upstream.example.com"
	const clientID = "es256-client"
	now := time.Now().UTC()
	idToken := signES256(t, key,
		map[string]any{"typ": "JWT", "alg": "ES256", "kid": "ec-key"},
		map[string]any{"iss": issuer, "sub": "user-1", "aud": clientID, "nonce": "n", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()},
	)

	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{Issuer: issuer, JWKSURI: jwksServer.URL, AllowedAlgorithms: []string{"ES256"}},
		Client:    http.DefaultClient,
		ClientID:  clientID,
	}
	claims, err := provider.verifyIDToken(context.Background(), idToken, "n")
	if err != nil {
		t.Fatalf("expected an allowed ES256 ID token to verify: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("unexpected subject: %v", claims["sub"])
	}
}

func TestOIDCVerifyIDTokenRejectsDisallowedAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "EC", "crv": "P-256", "kid": "ec-key",
			"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}}})
	}))
	defer jwksServer.Close()

	const issuer = "https://es256-upstream.example.com"
	const clientID = "es256-client"
	now := time.Now().UTC()
	idToken := signES256(t, key,
		map[string]any{"typ": "JWT", "alg": "ES256", "kid": "ec-key"},
		map[string]any{"iss": issuer, "sub": "user-1", "aud": clientID, "nonce": "n", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()},
	)

	// No AllowedAlgorithms set: defaults to RS256 only, so an otherwise
	// perfectly valid ES256 token must still be rejected.
	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{Issuer: issuer, JWKSURI: jwksServer.URL},
		Client:    http.DefaultClient,
		ClientID:  clientID,
	}
	if _, err := provider.verifyIDToken(context.Background(), idToken, "n"); err == nil {
		t.Fatal("expected an ES256 token to be rejected when only RS256 is allowed")
	}
}
