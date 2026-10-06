package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigSecureDefaults(t *testing.T) {
	for _, name := range []string{
		"MCP_AUTH_LOCAL_DEVELOPMENT", "MCP_AUTH_REQUIRE_HTTPS", "MCP_AUTH_REGISTRATION_ENABLED",
	} {
		t.Setenv(name, "")
	}
	config := ConfigFromEnv()
	if config.LocalDevelopment || !config.RequireHTTPS || config.RegistrationEnabled {
		t.Fatalf("insecure defaults: %+v", config)
	}
}

// TestConfigNormalizesTrailingSlashIssuer guards against a live bug found
// during real-client testing: a trailing-slash MCP_AUTH_ISSUER made
// authorizationMetadata's raw Issuer+"/token" concatenation and
// authenticateClientAssertion's separately-trimmed one disagree, so a
// client that built its assertion audience from the (correct, advertised)
// token_endpoint had its assertion rejected by the (differently
// constructed) expected audience. All endpoint derivation must go through
// Config's methods so there is exactly one computation to get right.
func TestConfigNormalizesTrailingSlashIssuer(t *testing.T) {
	config := Config{Issuer: "https://auth.example.com/", Resources: []string{"https://mcp.example.com"}, RequireHTTPS: true, PrivateKeyFile: "/keys/signing.pem", StoreBackend: "sqlite", DatabaseURL: "/data/auth.db"}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if config.Issuer != "https://auth.example.com" {
		t.Fatalf("expected the trailing slash to be stripped, got %q", config.Issuer)
	}
	if got := config.TokenEndpoint(); got != "https://auth.example.com/token" {
		t.Fatalf("unexpected token endpoint: %q", got)
	}
	if got := config.AuthorizationEndpoint(); got != "https://auth.example.com/authorize" {
		t.Fatalf("unexpected authorization endpoint: %q", got)
	}
	if got := config.IdentityCallbackURL(); got != "https://auth.example.com/identity/callback" {
		t.Fatalf("unexpected identity callback URL: %q", got)
	}
}

func TestConfigRejectsUnsafeDeployment(t *testing.T) {
	config := Config{Issuer: "https://auth.example.com", Resources: []string{"https://mcp.example.com"}, LocalDevelopment: true, RequireHTTPS: true}
	if err := config.Validate(); err == nil {
		t.Fatal("expected non-loopback local issuer to be rejected")
	}
	config = Config{Issuer: "https://auth.example.com", Resources: []string{"https://mcp.example.com"}, RequireHTTPS: true, StoreBackend: "memory"}
	if err := config.Validate(); err == nil {
		t.Fatal("expected production memory store to be rejected")
	}
}

func TestConnectorLoaderRejectsLiteralSecretAndAcceptsProviderConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(path, []byte(`{"bad":{"client_secret":"do-not-store"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConnectors(path); err == nil {
		t.Fatal("expected literal client secret to be rejected")
	}
	valid := `{"provider":{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token","jwks_uri":"https://idp.example.com/jwks","client_id":"client","scopes":["openid"],"exchange_client_id":"exchange","token_endpoint_auth_method":"none","allowed_client_redirect_uris":["https://client.example.com/callback"]}}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	connectors, err := LoadConnectors(path)
	if err != nil || connectors["provider"].Issuer != "https://idp.example.com" {
		t.Fatalf("load connector: %v", err)
	}
}

func TestConnectorClientIDEnvIndirection(t *testing.T) {
	direct := ConnectorConfig{ClientID: "literal-client"}
	clientID, err := direct.resolveClientID()
	if err != nil || clientID != "literal-client" {
		t.Fatalf("resolve literal client_id: %v, %q", err, clientID)
	}

	t.Setenv("TEST_CONNECTOR_CLIENT_ID", "  from-env  ")
	viaEnv := ConnectorConfig{ClientIDEnv: "TEST_CONNECTOR_CLIENT_ID"}
	clientID, err = viaEnv.resolveClientID()
	if err != nil || clientID != "from-env" {
		t.Fatalf("resolve client_id_env: %v, %q", err, clientID)
	}

	t.Setenv("TEST_CONNECTOR_CLIENT_ID_EMPTY", "")
	empty := ConnectorConfig{ClientIDEnv: "TEST_CONNECTOR_CLIENT_ID_EMPTY"}
	if _, err := empty.resolveClientID(); err == nil {
		t.Fatal("expected an empty client_id_env value to be rejected")
	}

	both := ConnectorConfig{Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/authorize", TokenEndpoint: "https://idp.example.com/token", JWKSURI: "https://idp.example.com/jwks", ClientID: "literal", ClientIDEnv: "TEST_CONNECTOR_CLIENT_ID", TokenEndpointAuthMethod: "none", ExchangeClientID: "exchange"}
	if err := both.validate("both", false); err == nil {
		t.Fatal("expected setting both client_id and client_id_env to be rejected")
	}
}

func TestRegisterEnforcesAllowedClientRedirectURIs(t *testing.T) {
	instance := testServer(t)
	instance.Config.RegistrationEnabled = true
	instance.Config.AllowedClientRedirectURIs = []string{"https://client.example.com/callback"}

	rejected := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"client_name":"x","redirect_uris":["https://not-allowed.example.com/callback"],"token_endpoint_auth_method":"none"}`))
	rejectedRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(rejectedRecorder, rejected)
	if rejectedRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected a redirect_uri outside the allowlist to be rejected, got %d: %s", rejectedRecorder.Code, rejectedRecorder.Body.String())
	}

	allowed := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"client_name":"x","redirect_uris":["https://client.example.com/callback"],"token_endpoint_auth_method":"none"}`))
	allowedRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code != http.StatusCreated {
		t.Fatalf("expected an allowlisted redirect_uri to succeed, got %d: %s", allowedRecorder.Code, allowedRecorder.Body.String())
	}
}

// TestSQLiteStoreMigratesPreviousSchema opens a database created with the
// original schema (version 0, unset PRAGMA user_version, predating
// public_key_pem/client_assertions/code_verifier/upstream_sessions) and
// asserts that NewSQLiteStore migrates it through every intermediate version
// in place instead of crash-looping, as it would against a real upgrade of a
// deployed database.
func TestSQLiteStoreMigratesPreviousSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
  token_endpoint_auth TEXT NOT NULL, secret_hash TEXT NOT NULL
);
CREATE TABLE authorization_codes (
  value_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
  subject TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL
);
CREATE TABLE refresh_tokens (
  value_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, subject TEXT NOT NULL,
  scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL, revoked INTEGER NOT NULL
);
CREATE TABLE consent_requests (
  value_hash TEXT PRIMARY KEY, request_json TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL
);
INSERT INTO clients (id,name,redirect_uris,token_endpoint_auth,secret_hash)
VALUES ('legacy-client','legacy','["https://client.example.com/callback"]','none','');
`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("migrate previous-version database: %v", err)
	}
	defer store.Close()

	// A client already in a pre-migration database was created through POST
	// /register, so its name is application-supplied and the consent page must
	// label it unverified. Migrating it to dynamic_registration = 0 would have
	// implied this server had verified that name. Operator-provisioned clients
	// are rewritten with DynamicRegistration false when startup reloads them.
	legacy, err := store.GetClient("legacy-client")
	if err != nil || !legacy.DynamicRegistration {
		t.Fatalf("pre-existing client should migrate as dynamically registered: %v, %+v", err, legacy)
	}
	if err := store.SaveClient(Client{ID: "resource-server", Resource: "https://mcp.example.com/mcp", TokenEndpointAuth: "private_key_jwt", PublicKeyPEM: "test"}); err != nil {
		t.Fatalf("save client using migrated column: %v", err)
	}
	client, err := store.GetClient("resource-server")
	if err != nil || client.PublicKeyPEM != "test" || client.Resource != "https://mcp.example.com/mcp" {
		t.Fatalf("resource client did not round-trip after migration: %v, %+v", err, client)
	}
	if err := store.SaveClient(Client{ID: "dyn-client", Name: "Dyn App", TokenEndpointAuth: "none", RedirectURIs: []string{"http://127.0.0.1:9/callback"}, DynamicRegistration: true}); err != nil {
		t.Fatalf("save dynamically registered client: %v", err)
	}
	dyn, err := store.GetClient("dyn-client")
	if err != nil || !dyn.DynamicRegistration || dyn.Name != "Dyn App" {
		t.Fatalf("dynamic registration did not round-trip after migration: %v, %+v", err, dyn)
	}
	if err := store.ConsumeClientAssertionJTI("resource-server", "jti-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("client_assertions table missing after migration: %v", err)
	}
	if err := store.SaveConsentRequest(ConsentRequest{ValueHash: HashSecret("state"), Nonce: "n", CodeVerifier: "verifier", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("save consent request using migrated column: %v", err)
	}
	consent, err := store.ConsumeConsentRequest("state", time.Now())
	if err != nil || consent.CodeVerifier != "verifier" {
		t.Fatalf("code_verifier did not round-trip after migration: %v, %+v", err, consent)
	}
	if err := store.SaveUpstreamSession("user-1", UpstreamSession{AccessToken: "a", RefreshToken: "r", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour), Scope: []string{"sql"}}); err != nil {
		t.Fatalf("upstream_sessions table missing after migration: %v", err)
	}
	session, err := store.GetUpstreamSession("user-1")
	if err != nil || session.AccessToken != "a" {
		t.Fatalf("upstream session did not round-trip after migration: %v, %+v", err, session)
	}
}

func TestSQLiteStorePersistsAndRotatesRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	client := Client{ID: "client", RedirectURIs: []string{"https://client.example.com/callback"}, TokenEndpointAuth: "none"}
	if err := store.SaveClient(client); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetClient(client.ID); err != nil {
		t.Fatal(err)
	}
	refresh := RefreshToken{ValueHash: HashSecret("refresh"), ClientID: client.ID, Subject: "user", Scope: []string{"tools:read"}, Resource: "https://mcp.example.com", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.SaveRefreshToken(refresh); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefreshToken("refresh", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefreshToken("refresh", time.Now()); !errors.Is(err, ErrAlreadyUsed) {
		t.Fatalf("expected reuse rejection, got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.GetClient(client.ID); err != nil {
		t.Fatalf("client did not persist: %v", err)
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	config := Config{Issuer: "http://localhost:8080", Resources: []string{"http://localhost:8081/mcp"}, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute, AllowedScopes: []string{"tools:read"}, RegistrationEnabled: true, LocalDevelopment: true, LocalSubject: "test-user"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Store.SaveClient(Client{ID: "client", RedirectURIs: []string{"http://localhost:9999/callback"}, TokenEndpointAuth: "none"}); err != nil {
		t.Fatal(err)
	}
	return instance
}

func TestMetadataAndJWKS(t *testing.T) {
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/jwks.json"} {
		recorder := httptest.NewRecorder()
		testServer(t).Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, recorder.Code)
		}
		if recorder.Header().Get("Cache-Control") == "" {
			t.Fatalf("%s: expected a Cache-Control header on a static metadata document", path)
		}
	}
}

func TestAuthorizationCodePKCE(t *testing.T) {
	instance := testServer(t)
	verifier := "test-verifier-1234567890"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp&scope=tools%3Aread&state=state&approve=true", nil)
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status: %d, body: %s", recorder.Code, recorder.Body.String())
	}
	code := recorder.Header().Get("Location")
	parsed, _ := url.Parse(code)
	authorizationCode := parsed.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {authorizationCode}, "redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {verifier}, "resource": {"http://localhost:8081/mcp"}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(tokenRecorder, tokenRequest)
	if tokenRecorder.Code != http.StatusOK {
		t.Fatalf("token status: %d, body: %s", tokenRecorder.Code, tokenRecorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(tokenRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["access_token"] == nil {
		t.Fatal("missing access token")
	}
}

func TestBadPKCERejected(t *testing.T) {
	instance := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge=bad&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp&approve=true", nil)
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	parsed, _ := url.Parse(recorder.Header().Get("Location"))
	code := parsed.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {code}, "redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {"wrong"}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(tokenRecorder, tokenRequest)
	if tokenRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", tokenRecorder.Code)
	}
}

func TestLoadResourceClientsValidatesPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resource-clients.json")
	if err := os.WriteFile(path, []byte(`[{"client_id":"bad","resource":"https://mcp.example.com/mcp","public_key_pem":"not-a-key"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResourceClients(path); err == nil {
		t.Fatal("expected an invalid public key to be rejected")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	valid := fmt.Sprintf(`[{"client_id":"resource-server","name":"demo-mcp","resource":"https://mcp.example.com/mcp","public_key_pem":%q}]`, string(publicPEM))
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	clients, err := LoadResourceClients(path)
	if err != nil || len(clients) != 1 || clients[0].ClientID != "resource-server" || clients[0].Resource != "https://mcp.example.com/mcp" {
		t.Fatalf("load resource clients: %v, %+v", err, clients)
	}
	withoutResource := fmt.Sprintf(`[{"client_id":"resource-server","public_key_pem":%q}]`, string(publicPEM))
	if err := os.WriteFile(path, []byte(withoutResource), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResourceClients(path); err == nil {
		t.Fatal("resource client without a bound resource was accepted")
	}
}

func TestPrivateKeyJWTClientCannotBypassAssertionViaFormClientID(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	registerResourceClient(t, instance, "resource-server", instance.Config.Resources[0])
	// No client_assertion at all: a private_key_jwt client has no secret, so
	// it must not fall through the "no secret configured" bypass meant for
	// TokenEndpointAuth "none" DCR clients.
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"whatever"}, "audience": {"https://downstream.example.com"}, "client_id": {"resource-server"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected a private_key_jwt client without an assertion to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTokenExchangeRequiresClientAuthentication(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"whatever"}, "audience": {"https://downstream.example.com"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated token exchange to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func registerResourceClient(t *testing.T, instance *Server, clientID, resource string) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := instance.Store.SaveClient(Client{ID: clientID, Resource: resource, TokenEndpointAuth: "private_key_jwt", PublicKeyPEM: string(publicPEM)}); err != nil {
		t.Fatal(err)
	}
	return key
}

func signTestClientAssertion(t *testing.T, key *rsa.PrivateKey, clientID, audience string) string {
	t.Helper()
	now := time.Now().UTC()
	header := map[string]any{"typ": "JWT", "alg": "RS256"}
	claims := map[string]any{"iss": clientID, "sub": clientID, "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": randomID()}
	headEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(header))
	claimEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	message := []byte(headEncoded + "." + claimEncoded)
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return string(message) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func exchangeForm(subjectToken, clientID, assertion string) url.Values {
	return url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":         {subjectToken},
		"audience":              {"https://downstream.example.com"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
}

func TestTokenExchangeWithValidPrivateKeyJWTSucceedsOnce(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	key := registerResourceClient(t, instance, "resource-server", instance.Config.Resources[0])
	subjectToken, err := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "user-1", instance.Config.Resources[0], []string{"tools:read"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form := exchangeForm(subjectToken, "resource-server", assertion)

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected exchange to succeed, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var exchanged map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &exchanged); err != nil {
		t.Fatal(err)
	}
	if exchanged["issued_token_type"] != issuedTokenTypeAccessToken {
		t.Fatalf("issued_token_type = %v, want %s", exchanged["issued_token_type"], issuedTokenTypeAccessToken)
	}

	replay := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected replayed client assertion to be rejected, got %d: %s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func TestTokenExchangeRejectsForeignSubjectToken(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	key := registerResourceClient(t, instance, "resource-server", instance.Config.Resources[0])
	assertion := signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form := exchangeForm("not-a-token-this-server-issued", "resource-server", assertion)

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected a fabricated subject_token to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTokenExchangeRejectsSubjectTokenForWrongResource(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	key := registerResourceClient(t, instance, "resource-server", instance.Config.Resources[0])
	subjectToken, err := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "user-1", "http://some-other-resource/mcp", []string{"tools:read"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form := exchangeForm(subjectToken, "resource-server", assertion)

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected a subject_token minted for a different resource to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTokenExchangeUsesConfiguredResourcesAndClientBinding(t *testing.T) {
	const first = "http://localhost:8081/first/mcp"
	const second = "http://localhost:8081/second/mcp"
	t.Setenv("MCP_AUTH_RESOURCES", first+","+second)
	// The removed single-resource setting must not influence issuance or exchange.
	t.Setenv("MCP_AUTH_RESOURCE", "http://localhost:8081/old/mcp")
	config := ConfigFromEnv()
	if len(config.Resources) != 2 || config.Resources[0] != first || config.Resources[1] != second {
		t.Fatalf("configured resources = %v", config.Resources)
	}
	config.LocalDevelopment = true
	config.RequireHTTPS = false
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "user-1"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	instance.TokenExchanger = LocalTokenExchanger{Issuer: config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	firstKey := registerResourceClient(t, instance, "first-client", first)
	secondKey := registerResourceClient(t, instance, "second-client", second)

	for _, tc := range []struct {
		name, resource, clientID string
		key                      *rsa.PrivateKey
		want                     int
	}{
		{"first resource", first, "first-client", firstKey, http.StatusOK},
		{"second resource through first client", second, "first-client", firstKey, http.StatusBadRequest},
		{"second resource", second, "second-client", secondKey, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subjectToken, err := instance.KeyProvider.Sign(context.Background(), config.Issuer, "user-1", tc.resource, []string{"tools:read"}, time.Minute, "")
			if err != nil {
				t.Fatal(err)
			}
			assertion := signTestClientAssertion(t, tc.key, tc.clientID, config.TokenEndpoint())
			request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(exchangeForm(subjectToken, tc.clientID, assertion).Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			instance.Handler().ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("exchange status = %d, want %d: %s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

func TestRequestLoggingRecordsMethodPathStatus(t *testing.T) {
	var output bytes.Buffer
	config := Config{Issuer: "http://localhost:8080", Resources: []string{"http://localhost:8081/mcp"}, AccessTokenTTL: time.Minute, AllowedScopes: []string{"tools:read"}, LocalDevelopment: true, LocalSubject: "test-user"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, &output)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	logged := output.String()
	if !strings.Contains(logged, `"method":"GET"`) || !strings.Contains(logged, `"path":"/healthz"`) || !strings.Contains(logged, `"status":200`) {
		t.Fatalf("expected a request log line for the health check, got: %s", logged)
	}
}

func TestRequestLoggingSilentDisablesIt(t *testing.T) {
	var output bytes.Buffer
	config := Config{Issuer: "http://localhost:8080", Resources: []string{"http://localhost:8081/mcp"}, AccessTokenTTL: time.Minute, AllowedScopes: []string{"tools:read"}, LocalDevelopment: true, LocalSubject: "test-user", LogLevel: "silent"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, &output)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if output.Len() != 0 {
		t.Fatalf("expected MCP_AUTH_LOG_LEVEL=silent to suppress request logging, got: %s", output.String())
	}
}

func TestAuditRedactsSecrets(t *testing.T) {
	var output bytes.Buffer
	logger := NewAuditLogger(&output)
	logger.Event("token_issued", "success", map[string]any{"client_id": "client", "access_token": "secret-token", "client_secret": "secret-value"})
	if strings.Contains(output.String(), "secret-token") || strings.Contains(output.String(), "secret-value") {
		t.Fatal("audit output contained a secret")
	}
}

// A path-mounted issuer must be discoverable the way RFC 8414 section 3.1
// specifies, which is also what this repo's own Go client asks for first
// (auth-client/go/mcpauth/discovery.go). Serving only the root form makes a
// deployment behind a path prefix undiscoverable without an ingress rewrite.
func TestPathMountedIssuerServesRFC8414Metadata(t *testing.T) {
	config := Config{
		Issuer:               "http://localhost:18080/mcp-auth",
		Resources:            []string{"http://localhost:18080/example/mcp"},
		AccessTokenTTL:       time.Minute,
		RefreshTokenTTL:      time.Hour,
		AuthorizationCodeTTL: time.Minute,
		AllowedScopes:        []string{"tools:read"},
		LocalDevelopment:     true,
		LocalSubject:         "test-user",
	}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	handler := instance.Handler()

	for _, path := range []string{
		"/.well-known/oauth-authorization-server/mcp-auth",
		"/.well-known/openid-configuration/mcp-auth",
		// The root form keeps existing deployments and OIDC-style clients working.
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", path, recorder.Code)
		}
		if body := recorder.Body.String(); !strings.Contains(body, `"issuer":"http://localhost:18080/mcp-auth"`) {
			t.Fatalf("%s: metadata did not advertise the configured issuer: %s", path, body)
		}
	}
}

func TestRootMountedIssuerRegistersNoPathRoute(t *testing.T) {
	recorder := httptest.NewRecorder()
	// testServer's issuer is http://localhost:8080, so there is no path segment
	// to append and nothing extra should be routed.
	testServer(t).Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server/anything", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404 for an unmounted issuer path", recorder.Code)
	}
}

func TestIssuerPath(t *testing.T) {
	for issuer, want := range map[string]string{
		"http://localhost:18080/mcp-auth":  "mcp-auth",
		"http://localhost:18080/mcp-auth/": "mcp-auth",
		"https://auth.example.com":         "",
		"https://auth.example.com/":        "",
		"https://auth.example.com/a/b":     "a/b",
	} {
		if got := (Config{Issuer: issuer}).IssuerPath(); got != want {
			t.Fatalf("IssuerPath(%q) = %q, want %q", issuer, got, want)
		}
	}
}

// The consent form must post to an issuer-derived URL. A root-relative action
// resolves against the browser's origin, so on a path-mounted deployment the
// browser drops the issuer prefix and posts to a 404 - the consent step failed
// even though /authorize itself had rendered fine.
func TestConsentFormPostsToTheIssuerMountedPath(t *testing.T) {
	config := Config{
		Issuer:               "http://localhost:18080/mcp-auth",
		Resources:            []string{"http://localhost:18080/ping/mcp"},
		AccessTokenTTL:       time.Minute,
		RefreshTokenTTL:      time.Hour,
		AuthorizationCodeTTL: time.Minute,
		AllowedScopes:        []string{"tools:read"},
		RegistrationEnabled:  true,
		LocalDevelopment:     true,
		LocalSubject:         "test-user",
	}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Store.SaveClient(Client{ID: "client", RedirectURIs: []string{"http://127.0.0.1:9999/callback"}, TokenEndpointAuth: "none"}); err != nil {
		t.Fatal(err)
	}

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {"client"},
		"redirect_uri":          {"http://127.0.0.1:9999/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"scope":                 {"tools:read"},
		"resource":              {"http://localhost:18080/ping/mcp"},
	}
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorize: got %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	want := `action="http://localhost:18080/mcp-auth/authorize/consent"`
	if !strings.Contains(body, want) {
		t.Fatalf("consent form does not post to the mounted path.\nwant: %s\ngot:  %s", want, body)
	}
	if strings.Contains(body, `action="/authorize/consent"`) {
		t.Fatalf("consent form still uses a root-relative action: %s", body)
	}
}

func TestConsentEndpoint(t *testing.T) {
	for issuer, want := range map[string]string{
		"http://localhost:18080/mcp-auth": "http://localhost:18080/mcp-auth/authorize/consent",
		"https://auth.example.com":        "https://auth.example.com/authorize/consent",
		"https://auth.example.com/":       "https://auth.example.com/authorize/consent",
	} {
		if got := (Config{Issuer: issuer}).ConsentEndpoint(); got != want {
			t.Fatalf("ConsentEndpoint(%q) = %q, want %q", issuer, got, want)
		}
	}
}

// RFC 7591 section 3.2.1: the registration response carries the registered
// client metadata, not just the identifier. A client that reads grant_types
// back to decide whether it may refresh sees an empty set otherwise and
// re-runs the whole authorization dance on every call.
func TestRegisterEchoesRegisteredMetadata(t *testing.T) {
	instance := testServer(t)
	body := `{"client_name":"probe","redirect_uris":["http://127.0.0.1:9999/callback"],` +
		`"grant_types":["authorization_code","refresh_token"],"response_types":["code"],` +
		`"token_endpoint_auth_method":"none"}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("register: got %d, want 201: %s", recorder.Code, recorder.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"client_id", "client_id_issued_at", "grant_types", "response_types", "scope"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("registration response is missing %q: %v", key, got)
		}
	}
	grants, _ := got["grant_types"].([]any)
	if len(grants) != 2 || grants[0] != "authorization_code" || grants[1] != "refresh_token" {
		t.Fatalf("grant_types = %v, want the two requested grants", got["grant_types"])
	}
	if types, _ := got["response_types"].([]any); len(types) != 1 || types[0] != "code" {
		t.Fatalf("response_types = %v, want [code]", got["response_types"])
	}
}

// A grant this server cannot honour must not be echoed back: promising it would
// have every token request for that grant fail after registration "succeeded".
func TestRegisterDropsUnsupportedGrants(t *testing.T) {
	if got := registeredGrantTypes([]string{"authorization_code", "implicit", "password"}); len(got) != 1 || got[0] != "authorization_code" {
		t.Fatalf("registeredGrantTypes dropped the wrong grants: %v", got)
	}
	// RFC 7591 section 2 default, plus the refresh token this server always issues.
	if got := registeredGrantTypes(nil); len(got) != 2 || got[0] != "authorization_code" || got[1] != "refresh_token" {
		t.Fatalf("default grant types = %v", got)
	}
}

// OpenID Connect Discovery 1.0 section 3 marks these REQUIRED, and this server
// serves the same document at /.well-known/openid-configuration. A client that
// validates against the OIDC schema - Cursor does - rejects the entire document
// when they are missing and never reaches an endpoint:
//
//	path: ["subject_types_supported"]  expected array, received undefined
func TestAuthorizationMetadataSatisfiesOIDCRequiredFields(t *testing.T) {
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		recorder := httptest.NewRecorder()
		testServer(t).Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: got %d", path, recorder.Code)
		}
		var metadata map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &metadata); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{
			"issuer",
			"authorization_endpoint",
			"token_endpoint",
			"jwks_uri",
			"response_types_supported",
			"subject_types_supported",
			"id_token_signing_alg_values_supported",
		} {
			value, ok := metadata[field]
			if !ok {
				t.Fatalf("%s: metadata is missing the required field %q", path, field)
			}
			if field == "subject_types_supported" || field == "id_token_signing_alg_values_supported" ||
				field == "response_types_supported" {
				list, isList := value.([]any)
				if !isList || len(list) == 0 {
					t.Fatalf("%s: %q must be a non-empty array, got %#v", path, field, value)
				}
			}
		}
	}
}

// RFC 9728 documents describe one resource. A multi-resource deployment that
// answers the bare well-known path with an arbitrary entry hands the client an
// audience it did not ask for, and every token it then gets is rejected by the
// server it meant to call.
func TestProtectedResourceMetadataIsPerResource(t *testing.T) {
	instance := multiResourceServer(t)

	if code, _ := getMetadata(t, instance, "/.well-known/oauth-protected-resource"); code != http.StatusNotFound {
		t.Fatalf("bare path with two resources = %d, want 404", code)
	}
	if code, _ := getMetadata(t, instance, "/.well-known/oauth-protected-resource/nope/mcp"); code != http.StatusNotFound {
		t.Fatalf("unknown resource = %d, want 404", code)
	}

	for path, want := range map[string]string{
		"/ping/mcp": "https://mcp.example.com/ping/mcp",
		"/echo/mcp": "https://mcp.example.com/echo/mcp",
	} {
		code, body := getMetadata(t, instance, "/.well-known/oauth-protected-resource"+path)
		if code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", path, code)
		}
		if body["resource"] != want {
			t.Fatalf("%s resource = %v, want %s", path, body["resource"], want)
		}
		if _, present := body["resources"]; present {
			t.Fatalf("%s still advertises the non-standard resources member: %v", path, body)
		}
		if servers, _ := body["authorization_servers"].([]any); len(servers) != 1 {
			t.Fatalf("%s authorization_servers = %v", path, body["authorization_servers"])
		}
	}
}

// A single-resource deployment stays answerable at the bare path.
func TestProtectedResourceMetadataBarePathForSingleResource(t *testing.T) {
	code, body := getMetadata(t, testServer(t), "/.well-known/oauth-protected-resource")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["resource"] != "http://localhost:8081/mcp" {
		t.Fatalf("resource = %v", body["resource"])
	}
	scopes, _ := body["scopes_supported"].([]any)
	if len(scopes) != 1 || scopes[0] != "tools:read" {
		t.Fatalf("scopes_supported = %v", body["scopes_supported"])
	}
	if methods, _ := body["bearer_methods_supported"].([]any); len(methods) != 1 || methods[0] != "header" {
		t.Fatalf("bearer_methods_supported = %v", body["bearer_methods_supported"])
	}
}

func multiResourceServer(t *testing.T) *Server {
	t.Helper()
	config := Config{Issuer: "http://localhost:8080", Resources: []string{"https://mcp.example.com/ping/mcp", "https://mcp.example.com/echo/mcp"}, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute, AllowedScopes: []string{"tools:read"}, RegistrationEnabled: true, LocalDevelopment: true, LocalSubject: "test-user"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func getMetadata(t *testing.T, instance *Server, path string) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder.Code, body
}

// X-Forwarded-Proto is set by the caller. Honouring it unconditionally turns
// RequireHTTPS into a header anyone who can reach this process may set, which
// is no guard at all — so it counts only when the deployment declares that a
// trusted proxy terminates TLS and is the only route in.
func TestHTTPSGuardIgnoresForwardedProtoUnlessProxyIsTrusted(t *testing.T) {
	for name, testCase := range map[string]struct {
		trustProxy bool
		forwarded  string
		want       int
	}{
		"untrusted proxy, spoofed header": {false, "https", http.StatusBadRequest},
		"untrusted proxy, no header":      {false, "", http.StatusBadRequest},
		"trusted proxy, header present":   {true, "https", http.StatusOK},
		"trusted proxy, header absent":    {true, "", http.StatusBadRequest},
		"trusted proxy, header is http":   {true, "http", http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			instance := testServer(t)
			instance.Config.RequireHTTPS = true
			instance.Config.TrustProxyTLS = testCase.trustProxy

			request := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
			if testCase.forwarded != "" {
				request.Header.Set("X-Forwarded-Proto", testCase.forwarded)
			}
			recorder := httptest.NewRecorder()
			instance.Handler().ServeHTTP(recorder, request)

			if recorder.Code != testCase.want {
				t.Fatalf("status = %d, want %d (body %s)", recorder.Code, testCase.want, recorder.Body.String())
			}
			if testCase.want == http.StatusBadRequest && !strings.Contains(recorder.Body.String(), "MCP_AUTH_TRUST_PROXY_TLS") {
				t.Fatalf("rejection should name the setting that fixes it, got %s", recorder.Body.String())
			}
		})
	}
}

type stubExchanger struct{ err error }

func (s stubExchanger) Exchange(context.Context, ExchangeRequest) (ExchangeResponse, error) {
	return ExchangeResponse{}, s.err
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "dial tcp: connection refused" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestTokenExchangeUpstreamFaultIsServerError(t *testing.T) {
	var output bytes.Buffer
	config := Config{Issuer: "http://localhost:8080", Resources: []string{"http://localhost:8081/mcp"}, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute, AllowedScopes: []string{"tools:read"}, RegistrationEnabled: true, LocalDevelopment: true, LocalSubject: "test-user"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, stubExchanger{err: fmt.Errorf("no upstream session for subject: missing")}, &output)
	if err != nil {
		t.Fatal(err)
	}
	key := registerResourceClient(t, instance, "resource-server", instance.Config.Resources[0])
	subjectToken, err := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "user-1", instance.Config.Resources[0], []string{"tools:read"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form := exchangeForm(subjectToken, "resource-server", assertion)
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("missing upstream session status = %d, want 502: %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "server_error" || body["error_description"] == "" {
		t.Fatalf("body = %#v, want server_error with a description", body)
	}
	if !strings.Contains(output.String(), `"reason":"no_upstream_session"`) {
		t.Fatalf("audit log missing exchange reason: %s", output.String())
	}

	output.Reset()
	instance.TokenExchanger = stubExchanger{err: timeoutNetError{}}
	var asNet net.Error = timeoutNetError{}
	if asNet.Timeout() != true {
		t.Fatal("timeout error must satisfy net.Error")
	}
	assertion = signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form = exchangeForm(subjectToken, "resource-server", assertion)
	request = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("upstream network status = %d, want 503: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(output.String(), `"reason":"upstream_unavailable"`) {
		t.Fatalf("audit log missing upstream_unavailable: %s", output.String())
	}

	output.Reset()
	instance.TokenExchanger = stubExchanger{err: ErrUnacceptableAudience}
	assertion = signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form = exchangeForm(subjectToken, "resource-server", assertion)
	request = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_target") {
		t.Fatalf("unacceptable audience = %d %s, want 400 invalid_target", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(output.String(), `"reason":"unacceptable_audience"`) {
		t.Fatalf("audit log missing unacceptable_audience: %s", output.String())
	}
}

func TestRegistrationFailureIsAudited(t *testing.T) {
	var output bytes.Buffer
	config := Config{Issuer: "http://localhost:8080", Resources: []string{"http://localhost:8081/mcp"}, AccessTokenTTL: time.Minute, AllowedScopes: []string{"tools:read"}, RegistrationEnabled: true, LocalDevelopment: true, LocalSubject: "test-user"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, &output)
	if err != nil {
		t.Fatal(err)
	}
	instance.Config.AllowedClientRedirectURIs = []string{"https://client.example.com/callback"}
	request := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"client_name":"x","redirect_uris":["https://nope.example.com/callback"],"token_endpoint_auth_method":"none"}`))
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	logged := output.String()
	if !strings.Contains(logged, `"event":"client_registration"`) || !strings.Contains(logged, `"reason":"redirect_uri_not_allowed"`) || !strings.Contains(logged, "https://nope.example.com/callback") {
		t.Fatalf("registration failure was not audited with reason and redirect_uri: %s", logged)
	}
}

func TestAuthorizeUnregisteredClientIsAudited(t *testing.T) {
	var output bytes.Buffer
	config := Config{Issuer: "http://localhost:8080", Resources: []string{"http://localhost:8081/mcp"}, AccessTokenTTL: time.Minute, AllowedScopes: []string{"tools:read"}, LocalDevelopment: true, LocalSubject: "test-user"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, &output)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/authorize?client_id=missing&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcallback", nil)
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	logged := output.String()
	if !strings.Contains(logged, `"event":"authorization_rejected"`) || !strings.Contains(logged, `"reason":"unregistered_client"`) || !strings.Contains(logged, "http://127.0.0.1:9/callback") {
		t.Fatalf("unregistered client was not audited: %s", logged)
	}
}
