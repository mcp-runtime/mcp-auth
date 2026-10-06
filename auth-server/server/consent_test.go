package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsentPageGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := renderConsentPage(&buf, fixedConsentView()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "consent_page.golden.html")
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if buf.String() != string(want) {
		t.Fatalf("consent page does not match %s", path)
	}
}

func TestConsentPageEscapesClientName(t *testing.T) {
	view := fixedConsentView()
	view.ClientName = `<script>alert(1)</script>`
	var buf bytes.Buffer
	if err := renderConsentPage(&buf, view); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("client name was not escaped: %s", body)
	}
	if strings.Contains(body, "<script>") {
		t.Fatalf("client name was inserted as markup: %s", body)
	}
}

func TestMissingScopeLabelFallsBackToRawScope(t *testing.T) {
	view := buildConsentView(&ConsentConfig{
		ScopeLabels: map[string]string{"tools:read": "Read data through tools"},
	}, "consent-id", "https://auth.example.com/authorize/consent", AuthorizationRequest{
		ClientID: "mcp_client",
		Scope:    []string{"tools:read", "custom:scope"},
		Resource: "https://mcp.example.com/mcp",
	}, Client{ID: "mcp_client", Name: "App"})
	var buf bytes.Buffer
	if err := renderConsentPage(&buf, view); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if !strings.Contains(body, `<span class="scope-description">Read data through tools</span>`) {
		t.Fatalf("labeled scope description missing: %s", body)
	}
	if !strings.Contains(body, `<span class="scope-raw">tools:read</span>`) {
		t.Fatalf("labeled scope raw value missing: %s", body)
	}
	if !strings.Contains(body, `<span class="scope-description">custom:scope</span>`) {
		t.Fatalf("unlabeled scope did not fall back to the raw scope: %s", body)
	}
	if strings.Contains(body, `<span class="scope-raw">custom:scope</span>`) {
		t.Fatalf("unlabeled scope duplicated the raw scope as a label: %s", body)
	}
}

func TestDefaultConsentPage(t *testing.T) {
	view := buildConsentView(nil, "consent-id", "https://auth.example.com/authorize/consent", AuthorizationRequest{
		ClientID: "client",
		Scope:    []string{"tools:read", "tools:write"},
		Resource: "https://mcp.example.com/mcp",
	}, Client{ID: "client", Name: "Local App"})
	var buf bytes.Buffer
	if err := renderConsentPage(&buf, view); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if len(body) < 1000 {
		t.Fatalf("default consent page is %d bytes", len(body))
	}
	for _, want := range []string{
		`<html lang="en">`,
		`name="viewport"`,
		`<title>Authorize access</title>`,
		`<main>`,
		`<h1>Local App</h1>`,
		`<ul class="scopes">`,
		`<span class="scope-description">tools:read</span>`,
		`<span class="scope-description">tools:write</span>`,
		`https://mcp.example.com/mcp`,
		`the upstream identity provider`,
		`method="post"`,
		`name="consent_id" value="consent-id"`,
		`name="decision" value="approve"`,
		`name="decision" value="deny"`,
		`action="https://auth.example.com/authorize/consent"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("default page missing %q", want)
		}
	}
	if strings.Contains(body, "has not been verified") {
		t.Fatalf("unverified notice rendered for a client that was not dynamically registered")
	}
	if strings.Contains(body, "tools:read tools:write") {
		t.Fatalf("scopes were rendered as one space-joined string")
	}
}

func TestConsentLinksRequireHTTPS(t *testing.T) {
	base := validTestConnector()
	rejected := []string{
		"http://example.com",
		"javascript:alert(1)",
		"data:text/html,hi",
		"//example.com/path",
		"/relative",
		"https://",
	}
	for _, bad := range rejected {
		website := base
		website.Consent = &ConsentConfig{WebsiteURL: bad}
		if err := website.validate("demo", true); err == nil {
			t.Fatalf("website_url %q was accepted", bad)
		}
		support := base
		support.Consent = &ConsentConfig{SupportURL: bad}
		if err := support.validate("demo", true); err == nil {
			t.Fatalf("support_url %q was accepted", bad)
		}
	}
	ok := base
	ok.Consent = &ConsentConfig{
		WebsiteURL: "https://inventory.example.com",
		SupportURL: "https://inventory.example.com/support",
	}
	if err := ok.validate("demo", false); err != nil {
		t.Fatal(err)
	}
	if err := base.validate("demo", false); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConnectorsParsesConsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connectors.json")
	body := `{
      "demo": {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
        "client_id": "client",
        "token_endpoint_auth_method": "none",
        "exchange_client_id": "exchange",
        "consent": {
          "display_name": "Inventory",
          "website_url": "https://inventory.example.com",
          "page_title": "Authorize Inventory",
          "subtitle": "Inventory access needs your approval.",
          "intro_paragraphs": ["Review the application before you continue."],
          "permissions": ["Read inventory records on your behalf"],
          "scope_labels": {"tools:read": "Read data through MCP tools"},
          "upstream_sso_label": "Example IdP",
          "support_url": "https://inventory.example.com/support"
        }
      }
    }`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	connectors, err := LoadConnectors(path)
	if err != nil {
		t.Fatal(err)
	}
	consent := connectors["demo"].Consent
	if consent == nil || consent.DisplayName != "Inventory" || consent.UpstreamSSOLabel != "Example IdP" {
		t.Fatalf("consent block was not parsed: %+v", consent)
	}
	if consent.ScopeLabels["tools:read"] != "Read data through MCP tools" {
		t.Fatalf("scope_labels: %+v", consent.ScopeLabels)
	}
	if consent.WebsiteURL != "https://inventory.example.com" || consent.SupportURL != "https://inventory.example.com/support" {
		t.Fatalf("consent links: %+v", consent)
	}

	rejected := strings.Replace(body, "https://inventory.example.com/support", "javascript:alert(1)", 1)
	if err := os.WriteFile(path, []byte(rejected), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConnectors(path); err == nil {
		t.Fatal("javascript support_url was accepted from the connectors file")
	}
}

func TestConsentDocumentSecurityHeaders(t *testing.T) {
	instance := testServer(t)
	instance.Config.Consent = &ConsentConfig{
		DisplayName:      "Inventory",
		ScopeLabels:      map[string]string{"tools:read": "Read data through tools"},
		UpstreamSSOLabel: "Example IdP",
	}
	recorder := authorizeConsent(t, instance, "client")
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorize: got %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	assertConsentHeaders(t, recorder)
	body := recorder.Body.String()
	for _, want := range []string{
		`<h1>Unnamed application</h1>`,
		"Read data through tools",
		"Example IdP",
		"http://localhost:8081/mcp",
		`name="consent_id" value="`,
		`name="decision" value="approve"`,
		`name="decision" value="deny"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("consent document missing %q", want)
		}
	}
}

func TestDynamicClientNameIsEscapedAndMarkedUnverified(t *testing.T) {
	instance := testServer(t)
	payload := `{"client_name":"<script>alert(1)</script>","redirect_uris":["http://127.0.0.1:9999/callback"],"token_endpoint_auth_method":"none"}`
	register := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	instance.Handler().ServeHTTP(register, request)
	if register.Code != http.StatusCreated {
		t.Fatalf("register: got %d: %s", register.Code, register.Body.String())
	}
	var created struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(register.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	recorder := authorizeConsent(t, instance, created.ClientID)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorize: got %d: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("dynamic client name was not escaped: %s", body)
	}
	if strings.Contains(body, "<script>") {
		t.Fatalf("dynamic client name was inserted as markup: %s", body)
	}
	if !strings.Contains(body, "This name was supplied by the application and has not been verified.") {
		t.Fatalf("dynamically registered client was not labeled unverified: %s", body)
	}
}

func TestExpiredConsentRendersHTML(t *testing.T) {
	instance := testServer(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/authorize/consent", strings.NewReader("consent_id=missing&decision=approve"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expired consent: got %d, want 400", recorder.Code)
	}
	assertConsentHeaders(t, recorder)
	body := recorder.Body.String()
	if !strings.Contains(body, "<html") || !strings.Contains(body, "<h1>This authorization request expired</h1>") {
		t.Fatalf("expired consent was not an HTML page: %s", body)
	}
	if !strings.Contains(body, "start again") {
		t.Fatalf("expired consent did not tell the user to start again: %s", body)
	}
	if strings.TrimSpace(body) == "consent request expired" {
		t.Fatalf("expired consent is still the plain-text error")
	}
	if !strings.Contains(recorder.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("content type %q", recorder.Header().Get("Content-Type"))
	}
}

func fixedConsentView() consentView {
	return buildConsentView(&ConsentConfig{
		DisplayName:      "Inventory",
		WebsiteURL:       "https://inventory.example.com",
		PageTitle:        "Authorize Inventory",
		Subtitle:         "Inventory access needs your approval.",
		IntroParagraphs:  []string{"Review the application and the access it is requesting before you continue.", "Deny the request if you do not recognize the application."},
		Permissions:      []string{"Read inventory records on your behalf", "Update stock counts"},
		ScopeLabels:      map[string]string{"tools:read": "Read data through MCP tools"},
		UpstreamSSOLabel: "Example IdP",
		SupportURL:       "https://inventory.example.com/support",
	}, "consent-fixed-id", "https://auth.example.com/authorize/consent", AuthorizationRequest{
		ClientID: "mcp_0123456789abcdef",
		Scope:    []string{"tools:read", "tools:write"},
		Resource: "https://mcp.example.com/inventory/mcp",
	}, Client{ID: "mcp_0123456789abcdef", Name: "Cursor", DynamicRegistration: true})
}

func validTestConnector() ConnectorConfig {
	return ConnectorConfig{
		Issuer:                  "https://idp.example.com",
		AuthorizationEndpoint:   "https://idp.example.com/authorize",
		TokenEndpoint:           "https://idp.example.com/token",
		JWKSURI:                 "https://idp.example.com/jwks",
		ClientID:                "client",
		TokenEndpointAuthMethod: "none",
		ExchangeClientID:        "exchange",
	}
}

func authorizeConsent(t *testing.T, instance *Server, clientID string) *httptest.ResponseRecorder {
	t.Helper()
	redirectURI := "http://127.0.0.1:9999/callback"
	if clientID == "client" {
		redirectURI = "http://localhost:9999/callback"
	}
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"scope":                 {"tools:read"},
		"resource":              {"http://localhost:8081/mcp"},
	}
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	return recorder
}

func assertConsentHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if got := recorder.Header().Get("Content-Security-Policy"); got != consentDocumentCSP {
		t.Fatalf("Content-Security-Policy = %q", got)
	}
	if strings.Contains(recorder.Header().Get("Content-Security-Policy"), "form-action") {
		t.Fatal("consent CSP must not block the redirect to the upstream identity provider")
	}
	if got := recorder.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}
