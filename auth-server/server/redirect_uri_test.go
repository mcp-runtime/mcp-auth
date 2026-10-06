package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestValidRedirectAcceptsNativeAppSchemes covers the redirect-URI shapes
// RFC 8252 defines for native apps. Private-use schemes (§7.1) and the IPv6
// loopback literal (§7.3) were both rejected before, which made dynamic client
// registration fail for every MCP desktop client: Claude Desktop registers
// claude://oauth/callback, Cursor registers cursor://..., and a client that
// binds ::1 rather than 127.0.0.1 was refused for doing the right thing.
func TestValidRedirectAcceptsNativeAppSchemes(t *testing.T) {
	accepted := []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://www.cursor.com/agents/mcp/oauth/callback",
		"http://127.0.0.1:39999/callback",
		"http://localhost:39999/callback",
		"http://[::1]:39999/callback",
		"claude://oauth/callback",
		"cursor://anysphere.cursor-retrieval/oauth/callback",
		"vscode://anysphere.cursor-retrieval/oauth/callback",
		"com.example.app:/oauth/callback",
	}
	for _, value := range accepted {
		if !validRedirect(value) {
			t.Errorf("validRedirect(%q) = false, want true", value)
		}
	}

	rejected := []string{
		"http://evil.example.com/callback", // plaintext off-loopback
		"http://10.0.0.5:8080/callback",    // plaintext off-loopback
		"https://example.com/cb#fragment",  // fragment
		"https://",                         // no host
		"not a url",                        // no scheme
		"",                                 // empty
		"/relative/callback",               // no scheme
	}
	for _, value := range rejected {
		if validRedirect(value) {
			t.Errorf("validRedirect(%q) = true, want false", value)
		}
	}
}

// TestRegisterAcceptsPrivateUseSchemeRedirect is the end-to-end form of the
// same regression: this exact request returned 400 invalid_redirect_uri, so a
// real client never obtained a client_id and reported only an empty transport
// error.
func TestRegisterAcceptsPrivateUseSchemeRedirect(t *testing.T) {
	config := Config{
		Issuer:              "http://127.0.0.1:8080",
		Resources:           []string{"http://127.0.0.1:8081/mcp"},
		LocalDevelopment:    true,
		RegistrationEnabled: true,
		StoreBackend:        "memory",
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	authServer, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "u"}, nil, bytes.NewBuffer(nil))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	for _, redirectURI := range []string{
		"claude://oauth/callback",
		"cursor://anysphere.cursor-retrieval/oauth/callback",
		"http://[::1]:39999/callback",
	} {
		body, _ := json.Marshal(map[string]any{
			"client_name":                "native client",
			"redirect_uris":              []string{redirectURI},
			"token_endpoint_auth_method": "none",
		})
		request := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		authServer.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusCreated {
			t.Errorf("POST /register with %q = %d (%s), want 201",
				redirectURI, recorder.Code, recorder.Body.String())
			continue
		}
		var response struct {
			ClientID string `json:"client_id"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Errorf("decode registration response for %q: %v", redirectURI, err)
			continue
		}
		if response.ClientID == "" {
			t.Errorf("registration for %q returned an empty client_id", redirectURI)
		}
	}
}

// documentedRedirectURIs are the redirect URIs the authorization-server docs
// tell an operator to put in allowed_client_redirect_uris. Copying that
// example has to pass config validation.
var documentedRedirectURIs = []string{
	"http://127.0.0.1:*",
	"http://localhost:*",
	"http://[::1]:*",
	"https://claude.ai/api/mcp/auth_callback",
	"https://www.cursor.com/agents/mcp/oauth/callback",
	"claude://oauth/callback",
	"cursor://anysphere.cursor-mcp/oauth/callback",
	"com.example.app:/oauth/callback",
}

func TestAllowlistAcceptsDocumentedRedirectURIs(t *testing.T) {
	connector := ConnectorConfig{
		Issuer:                    "https://idp.example.com",
		AuthorizationEndpoint:     "https://idp.example.com/authorize",
		TokenEndpoint:             "https://idp.example.com/token",
		JWKSURI:                   "https://idp.example.com/jwks",
		ClientID:                  "client",
		TokenEndpointAuthMethod:   "none",
		ExchangeClientID:          "exchange",
		AllowedClientRedirectURIs: append([]string(nil), documentedRedirectURIs...),
	}
	if err := connector.validate("example", false); err != nil {
		t.Fatalf("documented redirect allowlist: %v", err)
	}
	for _, value := range documentedRedirectURIs {
		if err := validAbsoluteURI(value); err != nil {
			t.Errorf("validAbsoluteURI(%q) = %v", value, err)
		}
		if !validRedirect(value) {
			t.Errorf("validRedirect(%q) = false", value)
		}
	}
	rejected := []string{"https://example.com/cb#fragment", "/relative/callback", "http://evil.example.com/callback"}
	for _, value := range rejected {
		if err := validAbsoluteURI(value); err == nil {
			t.Errorf("validAbsoluteURI(%q) accepted a URI that is not a redirect", value)
		}
		if validRedirect(value) {
			t.Errorf("validRedirect(%q) = true, want false", value)
		}
	}
}

func TestRegisterMatchesLoopbackPortAndExactOtherSchemes(t *testing.T) {
	instance := testServer(t)
	instance.Config.RegistrationEnabled = true
	instance.Config.AllowedClientRedirectURIs = []string{
		"http://127.0.0.1:*",
		"http://localhost:39999/callback",
		"https://client.example.com/callback",
		"com.example.app:/oauth/callback",
	}

	accepted := []string{
		"http://127.0.0.1:40000/callback",
		"http://127.0.0.1:39999/other",
		"http://localhost:40000/callback",
		"https://client.example.com/callback",
		"com.example.app:/oauth/callback",
	}
	for _, redirectURI := range accepted {
		if code, body := postRegister(instance, redirectURI); code != http.StatusCreated {
			t.Errorf("POST /register %q = %d (%s), want 201", redirectURI, code, body)
		}
	}
	rejected := []string{
		"http://localhost:39999/other",
		"https://client.example.com/other",
		"https://client.example.com:8443/callback",
		"com.example.app:/oauth/other",
		"http://[::1]:40000/callback",
	}
	for _, redirectURI := range rejected {
		if code, body := postRegister(instance, redirectURI); code != http.StatusBadRequest {
			t.Errorf("POST /register %q = %d (%s), want 400", redirectURI, code, body)
		}
	}
}

func postRegister(instance *Server, redirectURI string) (int, string) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                "native client",
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
	})
	request := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	return recorder.Code, recorder.Body.String()
}
