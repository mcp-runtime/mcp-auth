package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const extResource = "http://localhost:8081/gitlab/mcp"

type extEnv struct {
	server *Server
	key    *rsa.PrivateKey
}

func publicPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newExtEnv(t *testing.T, requiredScopes ...string) extEnv {
	t.Helper()
	config := Config{Issuer: "http://localhost:8080", Resources: []string{extResource, "http://localhost:8081/mcp"}, AccessTokenTTL: time.Minute,
		RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute, AllowedScopes: []string{"tools:read"},
		ResourceScopes: map[string][]string{extResource: {"gitlab:use", "gitlab:write"}}, LocalDevelopment: true, LocalSubject: "alice"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "alice"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Store.SaveClient(Client{ID: "client", RedirectURIs: []string{"http://localhost:9999/callback"}, TokenEndpointAuth: "none"}); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ext.json")
	body, _ := json.Marshal([]map[string]any{{
		"id": "gitlab-secrets", "resource": extResource, "required_scopes": requiredScopes,
		"resource_client": map[string]any{"client_id": "gitlab-plugin", "public_key_pem": publicPEM(t, key)},
	}})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadExternalCredentials(path, config.Resources, instance.Config.ScopesForResource)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.RegisterExternalCredentials(entries); err != nil {
		t.Fatal(err)
	}
	return extEnv{instance, key}
}

// login runs the real authorization-code flow and returns access and refresh tokens.
func (e extEnv) login(t *testing.T, scope string) (access, refresh string) {
	t.Helper()
	verifier := "test-verifier-1234567890"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://localhost:9999/callback"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {extResource}, "scope": {scope}, "state": {"s"}, "approve": {"true"}}
	rec := httptest.NewRecorder()
	e.server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {verifier}, "resource": {extResource}}
	rec = e.post(form)
	if rec.Code != http.StatusOK {
		t.Fatalf("login token: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out["access_token"].(string), out["refresh_token"].(string)
}

func (e extEnv) post(form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.server.Handler().ServeHTTP(rec, req)
	return rec
}

func (e extEnv) exchange(t *testing.T, subject string, mutate func(url.Values)) *httptest.ResponseRecorder {
	t.Helper()
	form := exchangeForm(subject, "gitlab-plugin", signTestClientAssertion(t, e.key, "gitlab-plugin", e.server.Config.Issuer+"/token"))
	form.Set("audience", extResource)
	form.Set("requested_token_type", CredentialAssertionTokenType)
	if mutate != nil {
		mutate(form)
	}
	return e.post(form)
}

func decodeJWT(t *testing.T, token string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	for i, dst := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, dst) != nil {
			t.Fatal("bad jwt")
		}
	}
	return
}

func TestExternalCredentialAssertionIssued(t *testing.T) {
	env := newExtEnv(t, "gitlab:use")
	access, _ := env.login(t, "gitlab:use")
	_, atClaims := decodeJWT(t, access)
	if atClaims["sid"] == "" || atClaims["sid"] == nil {
		t.Fatal("access token must carry a session id")
	}
	rec := env.exchange(t, access, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["issued_token_type"] != CredentialAssertionTokenType || body["token_type"] != "N_A" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response %v", body)
	}
	header, claims := decodeJWT(t, body["access_token"].(string))
	if header["typ"] != CredentialAssertionJWTType {
		t.Fatalf("typ = %v", header["typ"])
	}
	if claims["sub"] != "alice" || claims["iss"] != env.server.Config.Issuer || claims["aud"] != "gitlab-plugin" ||
		claims["resource"] != extResource || claims["sid"] != atClaims["sid"] {
		t.Fatalf("claims = %v", claims)
	}
	if exp := claims["exp"].(float64) - claims["iat"].(float64); exp != 60 {
		t.Fatalf("assertion ttl = %v", exp)
	}
	if _, ok := claims["access_token"]; ok {
		t.Fatal("no credential material expected")
	}
}

func TestExternalCredentialRejectsRevokedSession(t *testing.T) {
	env := newExtEnv(t)
	access, refresh := env.login(t, "gitlab:use")
	if err := env.server.Store.RevokeRefreshFamily(refresh); err != nil {
		t.Fatal(err)
	}
	if rec := env.exchange(t, access, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("revoked session: %d %s", rec.Code, rec.Body.String())
	}
}

func TestExternalCredentialSessionSurvivesRotationButNotRevokeOfCurrent(t *testing.T) {
	env := newExtEnv(t)
	access, refresh := env.login(t, "gitlab:use")
	rec := env.post(map[string][]string{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {refresh}})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if env.exchange(t, access, nil).Code != http.StatusOK {
		t.Fatal("old access token of a live session should still exchange")
	}
	if err := env.server.Store.RevokeRefreshToken(out["refresh_token"].(string)); err != nil {
		t.Fatal(err)
	}
	if env.exchange(t, access, nil).Code != http.StatusBadRequest {
		t.Fatal("session with no live refresh token must be inactive")
	}
}

func TestExternalCredentialRejections(t *testing.T) {
	env := newExtEnv(t, "gitlab:write")
	readOnly, _ := env.login(t, "gitlab:use")
	writer, _ := env.login(t, "gitlab:use gitlab:write")
	noSession, err := env.server.KeyProvider.Sign(context.Background(), env.server.Config.Issuer, "alice", extResource, []string{"gitlab:write"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	otherAudience, _ := env.server.KeyProvider.(SessionSigner).SignWithSession(context.Background(), env.server.Config.Issuer, "alice", "http://localhost:8081/mcp", []string{"gitlab:write"}, time.Minute, "x")
	foreignIssuer, _ := env.server.KeyProvider.(SessionSigner).SignWithSession(context.Background(), "https://evil.example", "alice", extResource, []string{"gitlab:write"}, time.Minute, "x")
	expired, _ := env.server.KeyProvider.(SessionSigner).SignWithSession(context.Background(), env.server.Config.Issuer, "alice", extResource, []string{"gitlab:write"}, -time.Minute, "x")
	assertion := env.exchange(t, writer, nil)
	var asBody map[string]any
	_ = json.Unmarshal(assertion.Body.Bytes(), &asBody)

	cases := map[string]struct {
		subject string
		mutate  func(url.Values)
		status  int
	}{
		"insufficient scope":       {readOnly, nil, http.StatusForbidden},
		"no session id":            {noSession, nil, http.StatusBadRequest},
		"other audience":           {otherAudience, nil, http.StatusBadRequest},
		"foreign issuer":           {foreignIssuer, nil, http.StatusBadRequest},
		"expired":                  {expired, nil, http.StatusBadRequest},
		"garbage":                  {"not-a-jwt", nil, http.StatusBadRequest},
		"assertion as subject":     {asBody["access_token"].(string), nil, http.StatusBadRequest},
		"wrong audience param":     {writer, func(v url.Values) { v.Set("audience", "http://localhost:8081/mcp") }, http.StatusBadRequest},
		"wrong requested type":     {writer, func(v url.Values) { v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token") }, http.StatusBadRequest},
		"missing requested type":   {writer, func(v url.Values) { v.Del("requested_token_type") }, http.StatusBadRequest},
		"wrong resource param":     {writer, func(v url.Values) { v.Set("resource", "http://localhost:8081/mcp") }, http.StatusBadRequest},
		"wrong subject token type": {writer, func(v url.Values) { v.Set("subject_token_type", "urn:x") }, http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := env.exchange(t, tc.subject, tc.mutate); rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestExternalCredentialClientAuthentication(t *testing.T) {
	env := newExtEnv(t)
	access, _ := env.login(t, "gitlab:use")

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	form := exchangeForm(access, "gitlab-plugin", signTestClientAssertion(t, other, "gitlab-plugin", env.server.Config.Issuer+"/token"))
	form.Set("audience", extResource)
	form.Set("requested_token_type", CredentialAssertionTokenType)
	if rec := env.post(form); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", rec.Code)
	}

	form = exchangeForm(access, "gitlab-plugin", signTestClientAssertion(t, env.key, "gitlab-plugin", env.server.Config.Issuer+"/token"))
	form.Set("audience", extResource)
	form.Set("requested_token_type", CredentialAssertionTokenType)
	if rec := env.post(form); rec.Code != http.StatusOK {
		t.Fatalf("first use: %d", rec.Code)
	}
	if rec := env.post(form); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed client assertion must be rejected, got %d", rec.Code)
	}

	// An unauthenticated caller cannot use the grant.
	rec := env.post(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {access}, "audience": {extResource}, "client_id": {"client"}})
	if rec.Code == http.StatusOK {
		t.Fatal("public client must not obtain an assertion")
	}
}

func TestExistingExchangeStillUsesTokenExchanger(t *testing.T) {
	env := newExtEnv(t)
	env.server.TokenExchanger = LocalTokenExchanger{Issuer: env.server.Config.Issuer, KeyProvider: env.server.KeyProvider, TTL: time.Minute}
	key := registerResourceClient(t, env.server, "plain-rs", "http://localhost:8081/mcp")
	subject, _ := env.server.KeyProvider.Sign(context.Background(), env.server.Config.Issuer, "alice", "http://localhost:8081/mcp", []string{"tools:read"}, time.Minute, "")
	form := exchangeForm(subject, "plain-rs", signTestClientAssertion(t, key, "plain-rs", env.server.Config.Issuer+"/token"))
	rec := env.post(form)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || body["issued_token_type"] != issuedTokenTypeAccessToken || body["token_type"] != "Bearer" {
		t.Fatalf("regression: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoadExternalCredentialsValidation(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := publicPEM(t, key)
	resources := []string{extResource}
	scopes := func(string) []string { return []string{"gitlab:use"} }
	entry := func(mutate func(m map[string]any)) string {
		m := map[string]any{"id": "gl", "resource": extResource, "required_scopes": []string{"gitlab:use"},
			"resource_client": map[string]any{"client_id": "plugin", "public_key_pem": pemKey}}
		mutate(m)
		path := filepath.Join(t.TempDir(), "x.json")
		data, _ := json.Marshal([]any{m})
		_ = os.WriteFile(path, data, 0o600)
		return path
	}
	if _, err := LoadExternalCredentials(entry(func(map[string]any) {}), resources, scopes); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := map[string]func(map[string]any){
		"unconfigured resource": func(m map[string]any) { m["resource"] = "http://other.example/mcp" },
		"scope not allowed":     func(m map[string]any) { m["required_scopes"] = []string{"nope"} },
		"bad id":                func(m map[string]any) { m["id"] = "has space" },
		"ttl too long":          func(m map[string]any) { m["assertion_ttl_seconds"] = 3600 },
		"missing client":        func(m map[string]any) { m["resource_client"] = map[string]any{"public_key_pem": pemKey} },
		"bad key": func(m map[string]any) {
			m["resource_client"] = map[string]any{"client_id": "p", "public_key_pem": "junk"}
		},
		"unknown field": func(m map[string]any) { m["vault"] = "op://x" },
	}
	for name, mutate := range bad {
		if _, err := LoadExternalCredentials(entry(mutate), resources, scopes); err == nil {
			t.Fatalf("%s: expected startup failure", name)
		}
	}
	if _, err := LoadExternalCredentials(filepath.Join(t.TempDir(), "missing.json"), resources, scopes); err == nil {
		t.Fatal("missing file must fail")
	}
	if entries, err := LoadExternalCredentials("", resources, scopes); err != nil || entries != nil {
		t.Fatal("empty path means disabled")
	}
}

func TestRefreshFamilyActiveSQLite(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	_ = store.SaveRefreshToken(RefreshToken{ValueHash: HashSecret("r1"), FamilyID: "f", ClientID: "c", ExpiresAt: now.Add(time.Hour)})
	if ok, _ := store.RefreshFamilyActive("f", now); !ok {
		t.Fatal("live family should be active")
	}
	if ok, _ := store.RefreshFamilyActive("f", now.Add(2*time.Hour)); ok {
		t.Fatal("expired family should be inactive")
	}
	_ = store.RevokeRefreshFamily("r1")
	if ok, _ := store.RefreshFamilyActive("f", now); ok {
		t.Fatal("revoked family should be inactive")
	}
	if ok, _ := store.RefreshFamilyActive("", now); ok {
		t.Fatal("empty family is never active")
	}
}
