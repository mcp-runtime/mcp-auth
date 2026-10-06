package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestResourceScopesBoundToRequestedAudience(t *testing.T) {
	instance := testServer(t)
	readURL := "http://localhost:8081/mcp"
	writeURL := "http://localhost:8081/cully/mcp"
	instance.Config.Resources = []string{readURL, writeURL}
	instance.Config.ResourceScopes = map[string][]string{
		readURL:  {"tools:read"},
		writeURL: {"tools:read", "tools:write"},
	}

	for _, tc := range []struct {
		resource string
		scope    string
		allowed  bool
	}{
		{readURL, "tools:read", true},
		{readURL, "tools:write", false},
		{writeURL, "tools:write", true},
	} {
		query := url.Values{
			"response_type": {"code"}, "client_id": {"client"},
			"redirect_uri":   {"http://localhost:9999/callback"},
			"code_challenge": {"challenge"}, "code_challenge_method": {"S256"},
			"resource": {tc.resource}, "scope": {tc.scope},
		}
		_, err := instance.parseAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
		if (err == nil) != tc.allowed {
			t.Fatalf("resource %s scope %s: allowed=%v, err=%v", tc.resource, tc.scope, tc.allowed, err)
		}
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/.well-known/oauth-protected-resource/mcp", "tools:read"},
		{"/.well-known/oauth-protected-resource/cully/mcp", "tools:write"},
	} {
		recorder := httptest.NewRecorder()
		instance.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("metadata %s: %d", tc.path, recorder.Code)
		}
		var body struct {
			Scopes []string `json:"scopes_supported"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !contains(body.Scopes, tc.want) || (tc.want == "tools:read" && contains(body.Scopes, "tools:write")) {
			t.Fatalf("metadata %s scopes = %v", tc.path, body.Scopes)
		}
	}

	// A refresh token must not keep granting a scope removed from the resource.
	recorder := httptest.NewRecorder()
	instance.issueTokens(recorder, httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("")).Context(), "client", "user", []string{"tools:write"}, readURL, "")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("removed scope issued a token: %d", recorder.Code)
	}
}

func TestResourceScopesConfigurationFailsClosed(t *testing.T) {
	base := Config{
		Issuer: "http://localhost:8080", Resource: "http://localhost:8081/mcp",
		LocalDevelopment: true, StoreBackend: "memory",
	}
	for _, raw := range []string{
		`{`,
		`{"http://localhost:8081/other/mcp":["tools:write"]}`,
		`{"http://localhost:8081/mcp":[]}`,
		`{"http://localhost:8081/mcp":["tools:read","tools:read"]}`,
	} {
		config := base
		config.ResourceScopesJSON = raw
		if err := config.Validate(); err == nil {
			t.Fatalf("accepted invalid resource scope mapping: %s", raw)
		}
	}
}

func TestConnectorDoesNotRequireMCPScopes(t *testing.T) {
	connector := ConnectorConfig{
		Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint: "https://idp.example.com/token", JWKSURI: "https://idp.example.com/jwks",
		ClientID: "client", TokenEndpointAuthMethod: "none", ExchangeClientID: "exchange",
	}
	if err := connector.validate("identity-only", false); err != nil {
		t.Fatalf("connector rejected without MCP scopes: %v", err)
	}
}
