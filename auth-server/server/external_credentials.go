package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// CredentialAccessAssertionTokenType is the requested_token_type that selects
// the external credential connector on the token-exchange grant.
const CredentialAccessAssertionTokenType = "urn:mcp-auth:token-type:credential-access-assertion"

const (
	defaultAssertionTTL = 60 * time.Second
	maxAssertionTTL     = 300 * time.Second
)

// ExternalCredential binds one separately deployed resource server (for
// example a secret-manager-backed MCP gateway) to an MCP resource. That
// resource server authenticates with private_key_jwt and may exchange a user's
// access token for a short-lived, signed credential-access assertion. This
// server never sees, stores or returns the upstream secret itself.
type ExternalCredential struct {
	ID                  string         `json:"id"`
	Resource            string         `json:"resource"`
	RequiredScopes      []string       `json:"required_scopes"`
	ResourceClient      ResourceClient `json:"resource_client"`
	AssertionTTLSeconds int            `json:"assertion_ttl_seconds"`
}

func (c ExternalCredential) assertionTTL() time.Duration {
	return time.Duration(c.AssertionTTLSeconds) * time.Second
}

// LoadExternalCredentials reads and validates the JSON array named by
// MCP_AUTH_EXTERNAL_CREDENTIALS_FILE. Everything is checked at startup so a bad
// file fails fast instead of at the first exchange. config must already be
// validated (resource scope policies parsed). An empty path returns nil.
func LoadExternalCredentials(path string, config Config) ([]ExternalCredential, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read external credentials file: %w", err)
	}
	var entries []ExternalCredential
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("parse external credentials file: %w", err)
	}
	resources := config.configuredResources()
	ids, clients := map[string]bool{}, map[string]bool{}
	for i := range entries {
		entry := &entries[i]
		if entry.ID == "" {
			return nil, errors.New("external credential is missing id")
		}
		if ids[entry.ID] {
			return nil, fmt.Errorf("external credential %q is duplicated", entry.ID)
		}
		ids[entry.ID] = true
		if parsed, err := url.Parse(entry.Resource); err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("external credential %q must name an absolute resource URL", entry.ID)
		}
		if !contains(resources, entry.Resource) {
			return nil, fmt.Errorf("external credential %q names resource %q that is not in MCP_AUTH_RESOURCES", entry.ID, entry.Resource)
		}
		if len(entry.RequiredScopes) == 0 {
			return nil, fmt.Errorf("external credential %q requires at least one required_scopes entry", entry.ID)
		}
		allowed := config.scopesForResource(entry.Resource)
		for _, scope := range entry.RequiredScopes {
			if !contains(allowed, scope) {
				return nil, fmt.Errorf("external credential %q requires scope %q that is not allowed for its resource", entry.ID, scope)
			}
		}
		client := &entry.ResourceClient
		if client.ClientID == "" {
			return nil, fmt.Errorf("external credential %q is missing resource_client.client_id", entry.ID)
		}
		if clients[client.ClientID] {
			return nil, fmt.Errorf("external credential resource client %q is duplicated", client.ClientID)
		}
		clients[client.ClientID] = true
		if client.Resource != "" && client.Resource != entry.Resource {
			return nil, fmt.Errorf("external credential %q resource_client.resource must match its resource", entry.ID)
		}
		client.Resource = entry.Resource
		if err := resolveResourceClientKey(client); err != nil {
			return nil, fmt.Errorf("external credential %q: %w", entry.ID, err)
		}
		if entry.AssertionTTLSeconds == 0 {
			entry.AssertionTTLSeconds = int(defaultAssertionTTL.Seconds())
		}
		if ttl := entry.assertionTTL(); ttl <= 0 || ttl > maxAssertionTTL {
			return nil, fmt.Errorf("external credential %q assertion_ttl_seconds must be between 1 and %d", entry.ID, int(maxAssertionTTL.Seconds()))
		}
	}
	return entries, nil
}

// EnableExternalCredentials activates the connector: it requires a key
// provider that can stamp sid into access tokens and sign assertions, and it
// registers each resource client so the token endpoint can authenticate it.
func (s *Server) EnableExternalCredentials(entries []ExternalCredential) error {
	if len(entries) == 0 {
		return nil
	}
	if _, ok := s.KeyProvider.(SessionSigner); !ok {
		return errors.New("external credentials require a key provider that supports session ids (SessionSigner)")
	}
	if _, ok := s.KeyProvider.(ClaimsSigner); !ok {
		return errors.New("external credentials require a key provider that can sign assertions (ClaimsSigner)")
	}
	byClient := make(map[string]ExternalCredential, len(entries))
	for _, entry := range entries {
		if err := s.Store.SaveClient(Client{
			ID:                entry.ResourceClient.ClientID,
			Name:              entry.ResourceClient.Name,
			Resource:          entry.Resource,
			TokenEndpointAuth: "private_key_jwt",
			PublicKeyPEM:      entry.ResourceClient.PublicKeyPEM,
			Algorithm:         entry.ResourceClient.Algorithm,
		}); err != nil {
			return fmt.Errorf("register external credential client %q: %w", entry.ResourceClient.ClientID, err)
		}
		byClient[entry.ResourceClient.ClientID] = entry
	}
	s.externalCredentials = byClient
	return nil
}

// exchangeExternalCredential serves the token-exchange grant for a resource
// client bound to an external credential. Every check runs before the
// assertion is signed, and nothing here talks to an upstream provider.
func (s *Server) exchangeExternalCredential(w http.ResponseWriter, r *http.Request, client Client, entry ExternalCredential) {
	fail := func(status int, code, reason string) {
		s.Audit.Event("credential_assertion", "failure", map[string]any{"client_id": client.ID, "credential_id": entry.ID, "resource": entry.Resource, "reason": reason})
		oauthError(w, status, code)
	}
	if client.Resource != entry.Resource {
		fail(http.StatusUnauthorized, "invalid_client", "resource_client_not_bound")
		return
	}
	if r.FormValue("requested_token_type") != CredentialAccessAssertionTokenType {
		fail(http.StatusBadRequest, "invalid_request", "requested_token_type_mismatch")
		return
	}
	if tokenType := r.FormValue("subject_token_type"); tokenType != "" && tokenType != issuedTokenTypeAccessToken {
		fail(http.StatusBadRequest, "invalid_request", "subject_token_type_mismatch")
		return
	}
	if r.FormValue("audience") != entry.Resource {
		fail(http.StatusBadRequest, "invalid_target", "audience_mismatch")
		return
	}
	claims, err := s.KeyProvider.Verify(r.Context(), r.FormValue("subject_token"))
	if err != nil {
		fail(http.StatusBadRequest, "invalid_grant", "invalid_subject_token")
		return
	}
	if claims["iss"] != s.Config.Issuer {
		fail(http.StatusBadRequest, "invalid_grant", "subject_token_issuer_mismatch")
		return
	}
	if !audienceContains(claims["aud"], entry.Resource) {
		fail(http.StatusBadRequest, "invalid_grant", "subject_token_audience_mismatch")
		return
	}
	subject, _ := claims["sub"].(string)
	scopeClaim, _ := claims["scope"].(string)
	granted := strings.Fields(scopeClaim)
	for _, required := range entry.RequiredScopes {
		if !contains(granted, required) {
			fail(http.StatusBadRequest, "invalid_grant", "insufficient_scope")
			return
		}
	}
	sid, _ := claims["sid"].(string)
	if subject == "" || sid == "" {
		fail(http.StatusBadRequest, "invalid_grant", "missing_session")
		return
	}
	active, err := s.Store.RefreshFamilyActive(sid, s.now())
	if err != nil {
		fail(http.StatusInternalServerError, "server_error", "session_lookup_failed")
		return
	}
	if !active {
		fail(http.StatusBadRequest, "invalid_grant", "session_inactive")
		return
	}
	now := s.now().UTC()
	ttl := entry.assertionTTL()
	assertion, err := s.KeyProvider.(ClaimsSigner).SignClaims(r.Context(), credentialAccessAssertionTyp, map[string]any{
		"iss": s.Config.Issuer, "sub": subject, "aud": client.ID, "sid": sid, "resource": entry.Resource,
		"scope": joinScopes(granted), "jti": randomID(), "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix(),
	})
	if err != nil {
		fail(http.StatusInternalServerError, "server_error", "signing_failed")
		return
	}
	s.Audit.Event("credential_assertion", "success", map[string]any{"client_id": client.ID, "credential_id": entry.ID, "subject": subject, "resource": entry.Resource, "family_id": sid})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      assertion,
		"issued_token_type": CredentialAccessAssertionTokenType,
		"token_type":        "N_A",
		"expires_in":        int(ttl.Seconds()),
		"scope":             joinScopes(granted),
	})
}
