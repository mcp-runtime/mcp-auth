package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// login runs authorize+token against the handler; scope "" omits the parameter.
func login(t *testing.T, instance *Server, scope string) map[string]any {
	t.Helper()
	verifier := "test-verifier-1234567890"
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://localhost:9999/callback"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
		"resource": {instance.Config.Resources[0]}, "state": {"s"}, "approve": {"true"}}
	if scope != "" {
		query.Set("scope", scope)
	}
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status %d: %s", recorder.Code, recorder.Body.String())
	}
	location, _ := url.Parse(recorder.Header().Get("Location"))
	return tokenCall(t, instance, http.StatusOK, url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"},
		"code": {location.Query().Get("code")}, "redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {verifier}})
}

func tokenCall(t *testing.T, instance *Server, want int, form url.Values) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != want {
		t.Fatalf("token status %d, want %d: %s", recorder.Code, want, recorder.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return body
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	return claims
}

func TestAuthorizeWithoutScopeDefaultsToResourceScopes(t *testing.T) {
	instance := testServer(t)
	body := login(t, instance, "")
	if body["scope"] != "tools:read" {
		t.Fatalf("response scope = %v", body["scope"])
	}
	if got := jwtClaims(t, body["access_token"].(string))["scope"]; got != "tools:read" {
		t.Fatalf("access token scope claim = %v, want tools:read", got)
	}
}

func TestRefreshReappliesAndNarrowsScope(t *testing.T) {
	instance := testServer(t)
	instance.Config.AllowedScopes = []string{"tools:read", "tools:write"}
	body := login(t, instance, "tools:read tools:write")
	refreshed := tokenCall(t, instance, http.StatusOK, url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {body["refresh_token"].(string)}})
	if refreshed["scope"] != "tools:read tools:write" {
		t.Fatalf("refresh scope = %v", refreshed["scope"])
	}
	narrowed := tokenCall(t, instance, http.StatusOK, url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {refreshed["refresh_token"].(string)}, "scope": {"tools:read"}})
	if narrowed["scope"] != "tools:read" {
		t.Fatalf("narrowed scope = %v", narrowed["scope"])
	}
	// Narrowed grant cannot be widened again.
	tokenCall(t, instance, http.StatusBadRequest, url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {narrowed["refresh_token"].(string)}, "scope": {"tools:write"}})
}

func TestRefreshOfLegacyEmptyScopeGrantGetsDefaults(t *testing.T) {
	instance := testServer(t)
	if err := instance.Store.SaveRefreshToken(RefreshToken{ValueHash: HashSecret("legacy"), FamilyID: "fam", ClientID: "client", Subject: "u", Resource: instance.Config.Resources[0], ExpiresAt: instance.now().Add(60e9)}); err != nil {
		t.Fatal(err)
	}
	body := tokenCall(t, instance, http.StatusOK, url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {"legacy"}})
	if body["scope"] != "tools:read" {
		t.Fatalf("legacy refresh scope = %v", body["scope"])
	}
}
