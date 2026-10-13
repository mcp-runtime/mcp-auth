package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// External credential connectors let a separately deployed resource server
// (for example a secret-manager-backed MCP gateway) obtain a short-lived,
// signed credential-access assertion for the authenticated user and one MCP
// resource. The authorization server never sees, stores or relays the
// upstream credential: it only decides, per exchange request, whether this
// resource client may act for this user's live session on this resource.
// Secret lookup stays entirely in the resource server.

const (
	// CredentialAssertionTokenType is the RFC 8693 requested_token_type and
	// issued_token_type of a credential-access assertion.
	CredentialAssertionTokenType = "urn:mcp-auth:token-type:credential-access-assertion"
	// CredentialAssertionJWTType is the JOSE typ of the assertion. It differs
	// from "at+jwt" so an assertion can never be accepted as an access token.
	CredentialAssertionJWTType = "credential-access+jwt"
	// credentialAssertionUse marks assertion claims so they are refused as a
	// subject_token even though they share the signing key.
	credentialAssertionUse = "credential_access"

	defaultAssertionTTL = 60 * time.Second
	maxAssertionTTL     = 300 * time.Second
)

var externalConnectorID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ExternalResourceClient identifies the resource server allowed to request
// assertions. Only its public key is configured.
type ExternalResourceClient struct {
	ClientID      string `json:"client_id"`
	PublicKeyPEM  string `json:"public_key_pem"`
	PublicKeyFile string `json:"public_key_file"`
	Algorithm     string `json:"algorithm"`
}

// ExternalCredentialConfig is one entry of MCP_AUTH_EXTERNAL_CREDENTIALS_FILE.
// It is provider-neutral: secret-manager details (vault references, service
// account tokens) belong to the external resource server's own configuration.
type ExternalCredentialConfig struct {
	ID                  string                 `json:"id"`
	Resource            string                 `json:"resource"`
	RequiredScopes      []string               `json:"required_scopes"`
	ResourceClient      ExternalResourceClient `json:"resource_client"`
	AssertionTTLSeconds int                    `json:"assertion_ttl_seconds"`
}

func (c ExternalCredentialConfig) assertionTTL() time.Duration {
	if c.AssertionTTLSeconds <= 0 {
		return defaultAssertionTTL
	}
	return time.Duration(c.AssertionTTLSeconds) * time.Second
}

// asResourceClient converts the entry into the shared private_key_jwt client
// registration so authentication reuses the existing token-endpoint path.
func (c ExternalCredentialConfig) asResourceClient() ResourceClient {
	return ResourceClient{
		ClientID:      c.ResourceClient.ClientID,
		Name:          c.ID,
		Resource:      c.Resource,
		PublicKeyPEM:  c.ResourceClient.PublicKeyPEM,
		PublicKeyFile: c.ResourceClient.PublicKeyFile,
		Algorithm:     c.ResourceClient.Algorithm,
	}
}

// LoadExternalCredentials reads and validates the connector file. resources
// is the configured resource allow-list; scopesFor returns the scopes a
// resource may be issued. Invalid configuration fails startup.
func LoadExternalCredentials(path string, resources []string, scopesFor func(string) []string) ([]ExternalCredentialConfig, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read external credentials file: %w", err)
	}
	var entries []ExternalCredentialConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("parse external credentials file: %w", err)
	}
	ids, bound, clientIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, entry := range entries {
		if !externalConnectorID.MatchString(entry.ID) {
			return nil, fmt.Errorf("external credential entry %d has an invalid id", i)
		}
		if ids[entry.ID] {
			return nil, fmt.Errorf("external credential %q is duplicated", entry.ID)
		}
		ids[entry.ID] = true
		parsed, err := url.Parse(entry.Resource)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("external credential %q must set an absolute resource URL", entry.ID)
		}
		if !contains(resources, entry.Resource) {
			return nil, fmt.Errorf("external credential %q binds unconfigured resource %q", entry.ID, entry.Resource)
		}
		if bound[entry.Resource] {
			return nil, fmt.Errorf("resource %q is bound to more than one external credential", entry.Resource)
		}
		bound[entry.Resource] = true
		allowed := scopesFor(entry.Resource)
		for _, scope := range entry.RequiredScopes {
			if scope == "" || !contains(allowed, scope) {
				return nil, fmt.Errorf("external credential %q requires a scope the resource does not allow", entry.ID)
			}
		}
		if entry.ResourceClient.ClientID == "" {
			return nil, fmt.Errorf("external credential %q is missing resource_client.client_id", entry.ID)
		}
		if clientIDs[entry.ResourceClient.ClientID] {
			return nil, fmt.Errorf("resource client %q is used by more than one external credential", entry.ResourceClient.ClientID)
		}
		clientIDs[entry.ResourceClient.ClientID] = true
		if entry.AssertionTTLSeconds < 0 || time.Duration(entry.AssertionTTLSeconds)*time.Second > maxAssertionTTL {
			return nil, fmt.Errorf("external credential %q assertion_ttl_seconds must be between 1 and %d", entry.ID, int(maxAssertionTTL.Seconds()))
		}
		client := entry.asResourceClient()
		if err := client.normalizeKey(); err != nil {
			return nil, err
		}
		entries[i].ResourceClient.PublicKeyPEM = client.PublicKeyPEM
		entries[i].ResourceClient.PublicKeyFile = ""
		entries[i].ResourceClient.Algorithm = client.Algorithm
	}
	return entries, nil
}

// RegisterExternalCredentials stores the resource clients and arms exchange
// dispatch. It fails when the key provider cannot sign assertions.
func (s *Server) RegisterExternalCredentials(entries []ExternalCredentialConfig) error {
	if len(entries) == 0 {
		return nil
	}
	if _, ok := s.KeyProvider.(ClaimsSigner); !ok {
		return errors.New("external credentials require a key provider that can sign credential assertions")
	}
	if _, ok := s.KeyProvider.(SessionSigner); !ok {
		return errors.New("external credentials require a key provider that issues session-bound access tokens")
	}
	registry := make(map[string]ExternalCredentialConfig, len(entries))
	for _, entry := range entries {
		client := entry.asResourceClient()
		if err := s.Store.SaveClient(Client{
			ID:                client.ClientID,
			Name:              client.Name,
			Resource:          client.Resource,
			TokenEndpointAuth: "private_key_jwt",
			PublicKeyPEM:      client.PublicKeyPEM,
			Algorithm:         client.Algorithm,
		}); err != nil {
			return fmt.Errorf("register external resource client %q: %w", client.ClientID, err)
		}
		registry[entry.Resource] = entry
	}
	s.ExternalCredentials = registry
	return nil
}

// exchangeExternal answers an RFC 8693 exchange from an authenticated
// external-credential resource client. Every call re-verifies the subject
// token and the live session, so a revoked session is refused before the
// resource server touches any secret store. Nothing is cached here.
func (s *Server) exchangeExternal(w http.ResponseWriter, r *http.Request, client Client, entry ExternalCredentialConfig) {
	fail := func(status int, code, reason string) {
		s.Audit.Event("credential_assertion", "failure", map[string]any{"client_id": client.ID, "connector": entry.ID, "reason": reason})
		oauthError(w, status, code)
	}
	if client.ID != entry.ResourceClient.ClientID {
		fail(http.StatusUnauthorized, "invalid_client", "resource_client_mismatch")
		return
	}
	if t := r.FormValue("requested_token_type"); t != CredentialAssertionTokenType {
		fail(http.StatusBadRequest, "invalid_request", "unsupported_requested_token_type")
		return
	}
	if t := r.FormValue("subject_token_type"); t != "" && t != "urn:ietf:params:oauth:token-type:access_token" {
		fail(http.StatusBadRequest, "invalid_request", "unsupported_subject_token_type")
		return
	}
	if r.FormValue("audience") != entry.Resource {
		fail(http.StatusBadRequest, "invalid_target", "audience_mismatch")
		return
	}
	if resource := r.FormValue("resource"); resource != "" && resource != entry.Resource {
		fail(http.StatusBadRequest, "invalid_target", "resource_mismatch")
		return
	}
	claims, err := s.KeyProvider.Verify(r.Context(), r.FormValue("subject_token"))
	if err != nil {
		fail(http.StatusBadRequest, "invalid_grant", "invalid_subject_token")
		return
	}
	subject, _ := claims["sub"].(string)
	sessionID, _ := claims["sid"].(string)
	issuer, _ := claims["iss"].(string)
	if _, isAssertion := claims["token_use"]; isAssertion || issuer != s.Config.Issuer || subject == "" ||
		!audienceContains(claims["aud"], entry.Resource) {
		fail(http.StatusBadRequest, "invalid_grant", "subject_token_rejected")
		return
	}
	granted := strings.Fields(fmt.Sprint(claims["scope"]))
	for _, scope := range entry.RequiredScopes {
		if !contains(granted, scope) {
			fail(http.StatusForbidden, "insufficient_scope", "missing_required_scope")
			return
		}
	}
	if sessionID == "" {
		fail(http.StatusBadRequest, "invalid_grant", "subject_token_has_no_session")
		return
	}
	active, err := s.Store.RefreshFamilyActive(sessionID, s.now())
	if err != nil {
		fail(http.StatusInternalServerError, "server_error", "session_lookup_failed")
		return
	}
	if !active {
		fail(http.StatusBadRequest, "invalid_grant", "session_inactive")
		return
	}
	ttl := entry.assertionTTL()
	now := s.now().UTC()
	assertion, err := s.KeyProvider.(ClaimsSigner).SignClaims(r.Context(), CredentialAssertionJWTType, map[string]any{
		"iss": s.Config.Issuer, "sub": subject, "aud": client.ID, "azp": client.ID,
		"resource": entry.Resource, "connector": entry.ID, "sid": sessionID,
		"scope": strings.Join(granted, " "), "token_use": credentialAssertionUse,
		"jti": randomID(), "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix(),
	})
	if err != nil {
		fail(http.StatusInternalServerError, "server_error", "signing_failed")
		return
	}
	s.Audit.Event("credential_assertion", "success", map[string]any{"client_id": client.ID, "connector": entry.ID, "subject": subject, "session": sessionID})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      assertion,
		"issued_token_type": CredentialAssertionTokenType,
		"token_type":        "N_A",
		"expires_in":        int(ttl.Seconds()),
		"scope":             strings.Join(granted, " "),
	})
}
