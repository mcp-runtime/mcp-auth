package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func externalCredentialServer(t *testing.T) (*Server, *rsa.PrivateKey) {
	t.Helper()
	instance := testServer(t)
	key := registerResourceClient(t, instance, "gateway", instance.Config.Resources[0])
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	err := instance.EnableExternalCredentials([]ExternalCredential{{
		ID: "vault", Resource: instance.Config.Resources[0], RequiredScopes: []string{"tools:read"}, AssertionTTLSeconds: 30,
		ResourceClient: ResourceClient{ClientID: "gateway", Resource: instance.Config.Resources[0], Algorithm: "RS256", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return instance, key
}

func assertionForm(instance *Server, key *rsa.PrivateKey, subjectToken string, t *testing.T) url.Values {
	return url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {subjectToken},
		"subject_token_type": {issuedTokenTypeAccessToken}, "requested_token_type": {CredentialAccessAssertionTokenType},
		"audience": {instance.Config.Resources[0]}, "client_id": {"gateway"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {signTestClientAssertion(t, key, "gateway", instance.Config.Issuer+"/token")},
	}
}

func TestAccessTokenCarriesSessionID(t *testing.T) {
	instance := testServer(t)
	claims := jwtClaims(t, login(t, instance, "tools:read")["access_token"].(string))
	if sid, _ := claims["sid"].(string); sid == "" {
		t.Fatalf("missing sid: %v", claims)
	}
}

func TestExternalCredentialAssertionIssued(t *testing.T) {
	instance, key := externalCredentialServer(t)
	access := login(t, instance, "tools:read")["access_token"].(string)
	body := tokenCall(t, instance, http.StatusOK, assertionForm(instance, key, access, t))
	if body["token_type"] != "N_A" || body["issued_token_type"] != CredentialAccessAssertionTokenType {
		t.Fatalf("unexpected response: %v", body)
	}
	assertion := body["access_token"].(string)
	claims := jwtClaims(t, assertion)
	subject := jwtClaims(t, access)
	if claims["aud"] != "gateway" || claims["sub"] != "test-user" || claims["sid"] != subject["sid"] || claims["resource"] != instance.Config.Resources[0] || claims["scope"] != "tools:read" || claims["jti"] == "" || claims["iss"] != instance.Config.Issuer {
		t.Fatalf("claims = %v", claims)
	}
	if ttl := claims["exp"].(float64) - claims["iat"].(float64); ttl != 30 {
		t.Fatalf("ttl = %v", ttl)
	}
	if strings.Split(assertion, ".")[0] == strings.Split(access, ".")[0] {
		t.Fatal("assertion must carry its own typ header")
	}
	// An assertion is not an access token and must not be exchangeable again.
	tokenCall(t, instance, http.StatusBadRequest, assertionForm(instance, key, assertion, t))
}

func TestExternalCredentialRejections(t *testing.T) {
	instance, key := externalCredentialServer(t)
	login1 := login(t, instance, "tools:read")
	access := login1["access_token"].(string)

	t.Run("revoked session", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(url.Values{"token": {login1["refresh_token"].(string)}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		instance.Handler().ServeHTTP(recorder, request)
		tokenCall(t, instance, http.StatusBadRequest, assertionForm(instance, key, access, t))
	})

	fresh := login(t, instance, "tools:read")["access_token"].(string)
	mutate := func(name string, edit func(url.Values), want int) {
		t.Run(name, func(t *testing.T) {
			form := assertionForm(instance, key, fresh, t)
			edit(form)
			tokenCall(t, instance, want, form)
		})
	}
	mutate("wrong requested_token_type", func(f url.Values) { f.Set("requested_token_type", issuedTokenTypeAccessToken) }, http.StatusBadRequest)
	mutate("wrong audience", func(f url.Values) { f.Set("audience", "https://other.example.com") }, http.StatusBadRequest)
	mutate("garbage subject token", func(f url.Values) { f.Set("subject_token", "a.b.c") }, http.StatusBadRequest)
	mutate("unauthenticated", func(f url.Values) { f.Del("client_assertion"); f.Del("client_assertion_type") }, http.StatusUnauthorized)

	t.Run("replayed client assertion", func(t *testing.T) {
		form := assertionForm(instance, key, fresh, t)
		tokenCall(t, instance, http.StatusOK, form)
		tokenCall(t, instance, http.StatusUnauthorized, form)
	})
	t.Run("foreign audience", func(t *testing.T) {
		token, _ := instance.KeyProvider.(SessionSigner).SignWithSession(context.Background(), instance.Config.Issuer, "u", "http://other/mcp", []string{"tools:read"}, time.Minute, "", "fam")
		tokenCall(t, instance, http.StatusBadRequest, assertionForm(instance, key, token, t))
	})
	t.Run("missing sid", func(t *testing.T) {
		token, _ := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "u", instance.Config.Resources[0], []string{"tools:read"}, time.Minute, "")
		tokenCall(t, instance, http.StatusBadRequest, assertionForm(instance, key, token, t))
	})
	t.Run("insufficient scope", func(t *testing.T) {
		instance.externalCredentials["gateway"] = func(e ExternalCredential) ExternalCredential {
			e.RequiredScopes = []string{"tools:write"}
			return e
		}(instance.externalCredentials["gateway"])
		tokenCall(t, instance, http.StatusBadRequest, assertionForm(instance, key, fresh, t))
	})
}

func TestNonExternalClientCannotRequestAssertion(t *testing.T) {
	instance := testServer(t)
	key := registerResourceClient(t, instance, "gateway", instance.Config.Resources[0])
	access := login(t, instance, "tools:read")["access_token"].(string)
	tokenCall(t, instance, http.StatusBadRequest, assertionForm(instance, key, access, t))
}

func TestRefreshFamilyActive(t *testing.T) {
	for name, store := range map[string]Store{"memory": NewMemoryStore(), "sqlite": func() Store {
		s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "s.db"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}()} {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			if ok, _ := store.RefreshFamilyActive("fam", now); ok {
				t.Fatal("unknown family active")
			}
			_ = store.SaveRefreshToken(RefreshToken{ValueHash: HashSecret("a"), FamilyID: "fam", ClientID: "c", ExpiresAt: now.Add(time.Hour)})
			if ok, _ := store.RefreshFamilyActive("fam", now); !ok {
				t.Fatal("live family inactive")
			}
			if ok, _ := store.RefreshFamilyActive("fam", now.Add(2*time.Hour)); ok {
				t.Fatal("expired family active")
			}
			_ = store.RevokeRefreshFamily("a")
			if ok, _ := store.RefreshFamilyActive("fam", now); ok {
				t.Fatal("revoked family active")
			}
		})
	}
}

func TestLoadExternalCredentialsValidates(t *testing.T) {
	config := Config{Resources: []string{"https://mcp.example.org/a"}, AllowedScopes: []string{"tools:read"}}
	key, _ := rsaKeyPEM(t)
	write := func(body string) string {
		path := filepath.Join(t.TempDir(), "ec.json")
		_ = os.WriteFile(path, []byte(body), 0o600)
		return path
	}
	entry := func(resource, scope, client string) string {
		return `{"id":"` + client + `","resource":"` + resource + `","required_scopes":["` + scope + `"],"resource_client":{"client_id":"` + client + `","public_key_pem":` + string(mustJSON(key)) + `}}`
	}
	good, err := LoadExternalCredentials(write("["+entry("https://mcp.example.org/a", "tools:read", "c1")+"]"), config)
	if err != nil || len(good) != 1 || good[0].AssertionTTLSeconds != 60 || good[0].ResourceClient.Resource != "https://mcp.example.org/a" {
		t.Fatalf("good = %+v, %v", good, err)
	}
	for name, body := range map[string]string{
		"unknown resource": "[" + entry("https://nope.example.org/a", "tools:read", "c1") + "]",
		"disallowed scope": "[" + entry("https://mcp.example.org/a", "tools:write", "c1") + "]",
		"duplicate client": "[" + entry("https://mcp.example.org/a", "tools:read", "c1") + "," + entry("https://mcp.example.org/a", "tools:read", "c1") + "]",
		"unknown field":    `[{"id":"x","vendor":"y"}]`,
	} {
		if _, err := LoadExternalCredentials(write(body), config); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func rsaKeyPEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	keys, err := NewKeyManager("")
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&keys.PrivateKey.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), keys.PrivateKey
}
