package mcpauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func typedToken(t *testing.T, key *rsa.PrivateKey, header map[string]any) string {
	t.Helper()
	header["alg"], header["kid"] = "RS256", "test"
	payload := b64JSON(map[string]any{"iss": "https://auth.example.com", "sub": "user", "aud": "client", "exp": time.Now().Add(time.Minute).Unix()})
	message := b64JSON(header) + "." + payload
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifierTokenTypeAllowlist(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := key.PublicKey
	newVerifier := func(types []string, require bool) *JWTVerifier {
		return &JWTVerifier{Issuer: "https://auth.example.com", Audience: "client", TokenTypes: types, RequireType: require,
			JWKSCacheTTL: time.Minute, keys: map[string]*rsa.PublicKey{"test": &public}, loadedAt: time.Now()}
	}
	cases := []struct {
		name     string
		verifier *JWTVerifier
		header   map[string]any
		ok       bool
	}{
		{"default accepts JWT", newVerifier(nil, false), map[string]any{"typ": "JWT"}, true},
		{"default accepts at+jwt", newVerifier(nil, false), map[string]any{"typ": "at+jwt"}, true},
		{"default rejects other typ", newVerifier(nil, false), map[string]any{"typ": "credential-access+jwt"}, false},
		{"default accepts untyped", newVerifier(nil, false), map[string]any{}, true},
		{"custom accepts its type", newVerifier([]string{"credential-access+jwt"}, true), map[string]any{"typ": "credential-access+jwt"}, true},
		{"custom rejects access token", newVerifier([]string{"credential-access+jwt"}, true), map[string]any{"typ": "at+jwt"}, false},
		{"require rejects untyped", newVerifier([]string{"credential-access+jwt"}, true), map[string]any{}, false},
		{"non-string typ", newVerifier(nil, false), map[string]any{"typ": 7}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.verifier.Verify(typedToken(t, key, tc.header))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestExchangeRequestedTokenTypeContextAndTypedError(t *testing.T) {
	var requested string
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		requested = r.PostForm.Get("requested_token_type")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"access_token":"assertion","token_type":"N_A","expires_in":60}`))
		} else {
			_, _ = w.Write([]byte(`{"error":"invalid_grant","detail":"secret-body"}`))
		}
	}))
	defer server.Close()

	client := &TokenExchangeClient{Endpoint: server.URL, AllowInsecure: true}
	if _, err := client.Exchange("subject", "aud", nil); err != nil || requested != accessTokenType {
		t.Fatalf("default type = %q err=%v", requested, err)
	}
	client.RequestedTokenType = "urn:example:assertion"
	token, err := client.ExchangeContext(context.Background(), "subject", "aud", nil)
	if err != nil || requested != "urn:example:assertion" || token.AccessToken != "assertion" {
		t.Fatalf("custom type = %q err=%v", requested, err)
	}

	status = http.StatusBadRequest
	_, err = client.ExchangeContext(context.Background(), "subject", "aud", nil)
	var exchangeErr *ExchangeError
	if !errors.As(err, &exchangeErr) || exchangeErr.Status != 400 || strings.Contains(err.Error(), "secret-body") {
		t.Fatalf("err = %v", err)
	}
	if err.Error() != "token exchange returned 400" {
		t.Fatalf("error text changed: %q", err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ExchangeContext(ctx, "subject", "aud", nil); err == nil {
		t.Fatal("a cancelled context must abort the exchange")
	}
}

func TestExchangeCacheKeySeparatesRequestedTypes(t *testing.T) {
	a := exchangeCacheKeyFor("s", "aud", nil, accessTokenType)
	b := exchangeCacheKeyFor("s", "aud", nil, "urn:example:assertion")
	if a == b || a != exchangeCacheKey("s", "aud", nil) {
		t.Fatal("cache keys must differ by requested type and stay stable for the default")
	}
}
