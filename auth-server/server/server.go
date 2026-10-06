package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Server struct {
	Config           Config
	Store            Store
	Keys             *KeyManager
	KeyProvider      KeyProvider
	IdentityProvider IdentityProvider
	TokenExchanger   TokenExchanger
	Audit            *AuditLogger
	// ClientMetadataClient fetches OAuth Client ID Metadata Documents.
	// Nil uses a client with a short timeout that does not follow redirects.
	ClientMetadataClient *http.Client
	now                  func() time.Time
}

type AuthorizationRequest struct {
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scope         []string `json:"scope"`
	State         string   `json:"state"`
	CodeChallenge string   `json:"code_challenge"`
	Resource      string   `json:"resource"`
	ResponseType  string   `json:"response_type"`
	Nonce         string   `json:"nonce"`
}

func NewServer(config Config, store Store, identityProvider IdentityProvider, exchanger TokenExchanger, auditWriter io.Writer) (*Server, error) {
	return NewServerWithKeyProvider(config, store, identityProvider, exchanger, nil, auditWriter)
}

func NewServerWithKeyProvider(config Config, store Store, identityProvider IdentityProvider, exchanger TokenExchanger, keyProvider KeyProvider, auditWriter io.Writer) (*Server, error) {
	if config.Issuer == "" || len(config.configuredResources()) == 0 {
		return nil, errors.New("issuer and resources are required")
	}
	if store == nil {
		store = NewMemoryStore()
	}
	if identityProvider == nil {
		if !config.LocalDevelopment {
			return nil, errors.New("identity provider is required outside local development")
		}
		identityProvider = LocalIdentityProvider{Subject: config.LocalSubject}
	}
	if auditWriter == nil {
		auditWriter = io.Discard
	}
	if keyProvider == nil {
		keys, err := NewKeyManager(config.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		keyProvider = LocalKeyProvider{Keys: keys}
		return &Server{Config: config, Store: store, Keys: keys, KeyProvider: keyProvider, IdentityProvider: identityProvider, TokenExchanger: exchanger, Audit: NewAuditLogger(auditWriter), now: time.Now}, nil
	}
	return &Server{Config: config, Store: store, KeyProvider: keyProvider, IdentityProvider: identityProvider, TokenExchanger: exchanger, Audit: NewAuditLogger(auditWriter), now: time.Now}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authorizationMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.authorizationMetadata)
	// RFC 8414 section 3.1: when the issuer carries a path, the metadata lives
	// at /.well-known/<name>/<issuer-path>, with the well-known segment between
	// the host and the path. A spec-following client - including this repo's own
	// Go client - asks for that URL first, so a path-mounted deployment that
	// serves only the two routes above is undiscoverable without an ingress
	// rewrite in front of it. Both forms are served: the root form keeps
	// existing deployments and OIDC-style clients working.
	if issuerPath := s.Config.IssuerPath(); issuerPath != "" {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server/"+issuerPath, s.authorizationMetadata)
		mux.HandleFunc("GET /.well-known/openid-configuration/"+issuerPath, s.authorizationMetadata)
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	// RFC 9728 section 3.1 forms the metadata URL by inserting the well-known
	// segment before the resource's path, so a resource at /ping/mcp is
	// described at /.well-known/oauth-protected-resource/ping/mcp.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{path...}", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("GET /identity/callback", s.identityCallback)
	// A deployment reusing a redirect URI its provider already accepts serves
	// the callback wherever that URI points. The default path stays mounted so
	// an existing deployment is unaffected.
	if callbackPath := s.Config.IdentityCallbackPath(); callbackPath != "/identity/callback" {
		mux.HandleFunc("GET "+callbackPath, s.identityCallback)
	}
	mux.HandleFunc("POST /authorize/consent", s.consent)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("POST /revoke", s.revoke)
	return s.requestLogging(s.cors(s.httpsOnly(mux)))
}

// requestLogging records one audit line per request (method, path, status,
// duration, client_id where the request carries one) so a failed connection
// attempt can be diagnosed from the log alone, without opening the store.
// Disabled by MCP_AUTH_LOG_LEVEL=silent for deployments that want quieter logs.
func (s *Server) requestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := randomID()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r = r.WithContext(context.WithValue(r.Context(), auditRequestIDKey{}, requestID))
		recorder.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(recorder, r)
		if strings.EqualFold(s.Config.LogLevel, "silent") {
			return
		}
		s.Audit.Request(requestID, r.Method, r.URL.Path, recorder.status, time.Since(start), r.FormValue("client_id"))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) authorizationMetadata(w http.ResponseWriter, _ *http.Request) {
	// This document changes only on redeploy, never per request; a client
	// that never sends a conditional request (most don't) would otherwise
	// refetch it on every connection attempt, which is indistinguishable in
	// the logs from a client retrying because something is actually failing.
	w.Header().Set("Cache-Control", "max-age=3600")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.Config.Issuer,
		"authorization_endpoint":                         s.Config.AuthorizationEndpoint(),
		"token_endpoint":                                 s.Config.TokenEndpoint(),
		"registration_endpoint":                          s.Config.RegistrationEndpoint(),
		"revocation_endpoint":                            s.Config.RevocationEndpoint(),
		"jwks_uri":                                       s.Config.JWKSURI(),
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		"scopes_supported":                               s.Config.supportedScopes(),
		"authorization_response_iss_parameter_supported": s.Config.AuthorizationResponseIssuer,
		"client_id_metadata_document_supported":          s.Config.ClientIDMetadataEnabled,
		// OpenID Connect Discovery 1.0 section 3 makes these REQUIRED, and the
		// same document is served at /.well-known/openid-configuration. A client
		// that validates against the OIDC schema - Cursor does - rejects the
		// whole document when they are absent and refuses to connect, long
		// before it ever reaches an endpoint.
		//
		// Both are honest here rather than decorative: this server issues one
		// non-pairwise subject per upstream identity, and signs with the single
		// RSA key it publishes at jwks_uri.
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

// protectedResourceMetadata serves RFC 9728 metadata for one resource.
//
// The document is per-resource: "resource" is a single audience a client will
// bind its token to. Answering the bare well-known path with an arbitrary entry
// from a multi-resource deployment hands the client the wrong audience and its
// tokens are then rejected by the server it meant to call, so the bare path is
// only answered when the deployment has exactly one resource. Everything else
// must address a resource by its path.
//
// Canonically this document belongs to the resource server, which knows the
// scopes it enforces. This endpoint is a convenience for deployments that front
// the authorization server and the resource on one host.
func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	resources := s.Config.configuredResources()
	resource, ok := matchResource(resources, r.PathValue("path"))
	if !ok {
		oauthError(w, http.StatusNotFound, "invalid_request")
		return
	}
	w.Header().Set("Cache-Control", "max-age=3600")
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{s.Config.Issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         s.Config.scopesForResource(resource),
	})
}

// matchResource resolves the resource a metadata request addresses. An empty
// path is the bare well-known URL, which is unambiguous only for a
// single-resource deployment.
func matchResource(resources []string, path string) (string, bool) {
	if path == "" {
		if len(resources) == 1 {
			return resources[0], true
		}
		return "", false
	}
	want := "/" + strings.Trim(path, "/")
	for _, resource := range resources {
		parsed, err := url.Parse(resource)
		if err != nil {
			continue
		}
		if "/"+strings.Trim(parsed.Path, "/") == want {
			return resource, true
		}
	}
	return "", false
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	keys, err := s.KeyProvider.JWKS(r.Context())
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Cache-Control", "max-age=3600")
	writeJSON(w, http.StatusOK, keys)
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	request, err := s.parseAuthorizationRequest(r)
	if err != nil {
		s.auditAuthorizationFailure(request, err)
		var metadata *clientMetadataError
		if errors.As(err, &metadata) {
			oauthErrorWithDescription(w, http.StatusBadRequest, "invalid_client", metadata.detail)
			return
		}
		oauthError(w, http.StatusBadRequest, err.Error())
		return
	}
	nonce := request.Nonce
	if nonce == "" {
		nonce = randomID()
	}
	consentID := randomID()
	if err := s.Store.SaveConsentRequest(ConsentRequest{ValueHash: HashSecret(consentID), Request: request, Nonce: nonce, ExpiresAt: s.now().Add(s.Config.AuthorizationCodeTTL)}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if s.Config.LocalDevelopment && r.URL.Query().Get("approve") == "true" {
		s.finishConsent(w, r, consentID, true)
		return
	}
	client, err := s.Store.GetClient(request.ClientID)
	if err != nil {
		client = Client{ID: request.ClientID}
	}
	setConsentDocumentHeaders(w)
	_ = renderConsentPage(w, buildConsentView(s.Config.Consent, consentID, s.Config.ConsentEndpoint(), request, client))
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid consent form")
		return
	}
	s.finishConsent(w, r, r.FormValue("consent_id"), r.FormValue("decision") == "approve")
}

func (s *Server) finishConsent(w http.ResponseWriter, r *http.Request, consentID string, approved bool) {
	pending, err := s.Store.ConsumeConsentRequest(consentID, s.now())
	if err != nil {
		writeExpiredConsent(w)
		return
	}
	request := pending.Request
	if !approved {
		redirectError(w, r, request, "access_denied", "consent was denied", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	if interactive, ok := s.IdentityProvider.(InteractiveIdentityProvider); ok {
		upstreamState := randomID()
		location, codeVerifier, err := interactive.Begin(r.Context(), IdentityRequest{
			ClientID: request.ClientID, Nonce: pending.Nonce, Resource: request.Resource, Scopes: request.Scope,
		}, upstreamState)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if err := s.Store.SaveConsentRequest(ConsentRequest{
			ValueHash: HashSecret(upstreamState), Request: request, Nonce: pending.Nonce,
			ExpiresAt: s.now().Add(s.Config.AuthorizationCodeTTL), CodeVerifier: codeVerifier,
		}); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	identity, err := s.IdentityProvider.Authenticate(r.Context(), IdentityRequest{ClientID: request.ClientID, Nonce: pending.Nonce, Resource: request.Resource, Scopes: request.Scope})
	if err != nil {
		redirectError(w, r, request, "access_denied", "identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	s.completeAuthorization(w, r, pending, identity)
}

func (s *Server) identityCallback(w http.ResponseWriter, r *http.Request) {
	interactive, ok := s.IdentityProvider.(InteractiveIdentityProvider)
	if !ok {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	pending, err := s.Store.ConsumeConsentRequest(state, s.now())
	if err != nil {
		http.Error(w, "identity state is invalid or expired", http.StatusBadRequest)
		return
	}
	if upstreamError := r.URL.Query().Get("error"); upstreamError != "" {
		s.Audit.Event("identity_callback", "failure", map[string]any{"reason": "upstream_error", "error_type": upstreamError})
		redirectError(w, r, pending.Request, "access_denied", "upstream identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	identity, err := interactive.Complete(r.Context(), IdentityCallback{
		Code: r.URL.Query().Get("code"), RedirectURI: s.Config.IdentityCallbackURL(), Nonce: pending.Nonce, State: state,
		CodeVerifier: pending.CodeVerifier,
	})
	if err != nil {
		// Complete errors are deliberately kept out of the browser response, but
		// the sanitized error text is needed to diagnose provider configuration
		// without logging the authorization code, token, or client secret.
		s.Audit.Event("identity_callback", "failure", map[string]any{"reason": err.Error()})
		redirectError(w, r, pending.Request, "access_denied", "upstream identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	s.completeAuthorization(w, r, pending, identity)
}

func (s *Server) completeAuthorization(w http.ResponseWriter, r *http.Request, pending ConsentRequest, identity Identity) {
	request := pending.Request
	if identity.UpstreamSession != nil {
		if err := s.Store.SaveUpstreamSession(identity.Subject, *identity.UpstreamSession); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	code := randomID()
	if err := s.Store.SaveAuthorizationCode(AuthorizationCode{
		ValueHash: HashSecret(code), ClientID: request.ClientID, RedirectURI: request.RedirectURI,
		CodeChallenge: request.CodeChallenge, Scope: request.Scope, Resource: request.Resource,
		Subject: identity.Subject, Nonce: pending.Nonce, ExpiresAt: s.now().Add(s.Config.AuthorizationCodeTTL),
	}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	s.Audit.Event("authorization_code_issued", "success", map[string]any{"client_id": request.ClientID, "subject": identity.Subject})
	location, _ := url.Parse(request.RedirectURI)
	query := location.Query()
	query.Set("code", code)
	if request.State != "" {
		query.Set("state", request.State)
	}
	if s.Config.AuthorizationResponseIssuer {
		query.Set("iss", s.Config.Issuer)
	}
	location.RawQuery = query.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) parseAuthorizationRequest(r *http.Request) (AuthorizationRequest, error) {
	q := r.URL.Query()
	request := AuthorizationRequest{ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), CodeChallenge: q.Get("code_challenge"), Resource: q.Get("resource"), ResponseType: q.Get("response_type"), Nonce: q.Get("nonce"), Scope: strings.Fields(q.Get("scope"))}
	client, err := s.resolveClient(r.Context(), request.ClientID)
	if err != nil {
		return request, err
	}
	if request.ResponseType != "code" || request.CodeChallenge == "" || q.Get("code_challenge_method") != "S256" {
		return request, fmt.Errorf("code, response_type=code, and S256 PKCE are required")
	}
	if !s.clientRedirectPermitted(client, request.RedirectURI) || !validRedirect(request.RedirectURI) {
		return request, fmt.Errorf("redirect_uri is not registered")
	}
	resources := s.Config.configuredResources()
	if request.Resource == "" && len(resources) == 1 {
		request.Resource = resources[0]
	}
	if !contains(resources, request.Resource) {
		return request, fmt.Errorf("resource is not recognized")
	}
	allowedScopes := s.Config.scopesForResource(request.Resource)
	for _, scope := range request.Scope {
		if !contains(allowedScopes, scope) {
			return request, fmt.Errorf("scope is not allowed")
		}
	}
	return request, nil
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid form")
		return
	}
	client, err := s.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.authorizationCodeToken(w, r, client)
	case "refresh_token":
		s.refreshTokenToken(w, r, client)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		s.exchange(w, r, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (s *Server) authorizationCodeToken(w http.ResponseWriter, r *http.Request, client Client) {
	code, err := s.Store.ConsumeAuthorizationCode(r.FormValue("code"), s.now())
	if err != nil || code.ClientID != r.FormValue("client_id") || code.RedirectURI != r.FormValue("redirect_uri") || !s.clientRedirectPermitted(client, code.RedirectURI) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	verifier := r.FormValue("code_verifier")
	if !validPKCE(verifier, code.CodeChallenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	resource := r.FormValue("resource")
	if resource == "" {
		resource = code.Resource
	}
	if resource != code.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return
	}
	s.issueTokens(w, r.Context(), code.ClientID, code.Subject, code.Scope, resource, "")
}

type auditRequestIDKey struct{}

func refreshAuditAttrs(r *http.Request, clientID string, token RefreshToken, reason string) map[string]any {
	attrs := map[string]any{"grant_type": "refresh_token", "client_id": clientID, "reason": reason}
	if id, ok := r.Context().Value(auditRequestIDKey{}).(string); ok {
		attrs["request_id"] = id
	}
	if token.FamilyID != "" {
		attrs["family_id"] = token.FamilyID
	}
	if token.Resource != "" {
		attrs["resource"] = token.Resource
	}
	return attrs
}

func (s *Server) refreshTokenToken(w http.ResponseWriter, r *http.Request, client Client) {
	old := r.FormValue("refresh_token")
	token, err := s.Store.ConsumeRefreshTokenForClient(old, client.ID, s.now())
	if err != nil {
		reason := "store_error"
		switch {
		case errors.Is(err, ErrRefreshClientMismatch):
			reason = "client_mismatch"
		case errors.Is(err, ErrRefreshRevoked):
			reason = "revoked"
		case errors.Is(err, ErrRefreshExpired):
			reason = "expired"
		case errors.Is(err, ErrAlreadyUsed):
			reason = "replay"
		case errors.Is(err, ErrNotFound):
			reason = "unknown"
		}
		s.Audit.Event("refresh_rejected", "failure", refreshAuditAttrs(r, client.ID, token, reason))
		if errors.Is(err, ErrAlreadyUsed) {
			outcome, revokeReason := "success", "replay"
			if revokeErr := s.Store.RevokeRefreshFamily(old); revokeErr != nil {
				outcome, revokeReason = "failure", "store_error"
			}
			s.Audit.Event("refresh_family_revoked", outcome, refreshAuditAttrs(r, client.ID, token, revokeReason))
			if outcome != "success" {
				oauthError(w, http.StatusInternalServerError, "server_error")
				return
			}
		}
		if reason == "store_error" {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	outcome, reason := "success", "rotated"
	if !s.issueTokens(w, r.Context(), token.ClientID, token.Subject, token.Scope, token.Resource, token.FamilyID) {
		outcome, reason = "failure", "issuance_failed"
	}
	s.Audit.Event("refresh_rotated", outcome, refreshAuditAttrs(r, client.ID, token, reason))
}

func (s *Server) issueTokens(w http.ResponseWriter, ctx context.Context, clientID, subject string, scopes []string, resource, familyID string) bool {
	if !contains(s.Config.configuredResources(), resource) {
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return false
	}
	allowedScopes := s.Config.scopesForResource(resource)
	for _, scope := range scopes {
		if !contains(allowedScopes, scope) {
			oauthError(w, http.StatusBadRequest, "invalid_scope")
			return false
		}
	}
	access, err := s.KeyProvider.Sign(ctx, s.Config.Issuer, subject, resource, scopes, s.Config.AccessTokenTTL, "")
	if err != nil {
		s.Audit.Event("token_issue", "failure", map[string]any{"reason": "signing_failed"})
		oauthError(w, http.StatusInternalServerError, "server_error")
		return false
	}
	refresh := randomID()
	if familyID == "" {
		familyID = randomID()
	}
	if err := s.Store.SaveRefreshToken(RefreshToken{ValueHash: HashSecret(refresh), FamilyID: familyID, ClientID: clientID, Subject: subject, Scope: scopes, Resource: resource, ExpiresAt: s.now().Add(s.Config.RefreshTokenTTL)}); err != nil {
		s.Audit.Event("token_issue", "failure", map[string]any{"reason": "refresh_persistence_failed"})
		oauthError(w, http.StatusInternalServerError, "server_error")
		return false
	}
	s.Audit.Event("token_issued", "success", map[string]any{"client_id": clientID, "subject": subject, "resource": resource, "family_id": familyID})
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(s.Config.AccessTokenTTL.Seconds()), "refresh_token": refresh, "scope": strings.Join(scopes, " ")})
	return true
}

// exchange handles RFC 8693 token exchange. The caller has already
// authenticated as client (see authenticateClient); this additionally
// verifies that subject_token is a still-valid access token this server
// itself issued for the authenticated resource client's bound resource, rather than relaying an arbitrary
// caller-supplied string to the upstream provider.
func (s *Server) exchange(w http.ResponseWriter, r *http.Request, client Client) {
	if s.TokenExchanger == nil {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	if client.TokenEndpointAuth != "private_key_jwt" || client.Resource == "" || !contains(s.Config.configuredResources(), client.Resource) {
		s.Audit.Event("token_exchange", "failure", map[string]any{"client_id": client.ID, "reason": "resource_client_not_bound"})
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	subjectToken := r.FormValue("subject_token")
	subjectClaims, err := s.KeyProvider.Verify(r.Context(), subjectToken)
	if err != nil {
		s.Audit.Event("token_exchange", "failure", map[string]any{"client_id": client.ID, "audience": r.FormValue("audience"), "reason": "invalid_subject_token"})
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if subjectClaims["aud"] != client.Resource {
		s.Audit.Event("token_exchange", "failure", map[string]any{"client_id": client.ID, "audience": r.FormValue("audience"), "reason": "subject_token_audience_mismatch"})
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	subject, _ := subjectClaims["sub"].(string)
	response, err := s.TokenExchanger.Exchange(r.Context(), ExchangeRequest{Subject: subject, SubjectToken: subjectToken, RequestedTokenType: r.FormValue("requested_token_type"), Audience: r.FormValue("audience"), Scope: strings.Fields(r.FormValue("scope"))})
	if err != nil {
		status, reason, description := classifyExchangeError(err)
		s.Audit.Event("token_exchange", "failure", map[string]any{"client_id": client.ID, "audience": r.FormValue("audience"), "reason": reason})
		if reason == "unacceptable_audience" {
			oauthError(w, status, "invalid_target")
			return
		}
		oauthErrorWithDescription(w, status, "server_error", description)
		return
	}
	s.Audit.Event("token_exchange", "success", map[string]any{"client_id": client.ID, "subject": subjectClaims["sub"], "audience": r.FormValue("audience")})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      response.AccessToken,
		"issued_token_type": issuedTokenTypeAccessToken,
		"token_type":        response.TokenType,
		"expires_in":        response.ExpiresIn,
		"scope":             response.Scope,
	})
}

// issuedTokenTypeAccessToken is the RFC 8693 §2.2.1 token type this endpoint returns.
const issuedTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

// ErrUnacceptableAudience is returned by a TokenExchanger when the requested
// audience itself is not acceptable. Other exchanger errors are upstream faults
// and must not be reported as invalid_target.
var ErrUnacceptableAudience = errors.New("unacceptable audience")

func classifyExchangeError(err error) (status int, reason, description string) {
	if errors.Is(err, ErrUnacceptableAudience) {
		return http.StatusBadRequest, "unacceptable_audience", "the requested audience is not acceptable"
	}
	var netErr net.Error
	message := err.Error()
	switch {
	case errors.As(err, &netErr):
		return http.StatusServiceUnavailable, "upstream_unavailable", "the upstream token endpoint could not be reached"
	case strings.Contains(message, "no upstream session"):
		return http.StatusBadGateway, "no_upstream_session", "no upstream session is stored for this subject"
	case strings.Contains(message, "HTTP 503"), strings.Contains(message, "HTTP 502"):
		return http.StatusServiceUnavailable, "upstream_unavailable", "the upstream token endpoint is unavailable"
	case strings.Contains(message, "HTTP 5"):
		return http.StatusBadGateway, "upstream_error", "the upstream token endpoint returned an error"
	default:
		return http.StatusBadGateway, "upstream_exchange_failed", "the upstream token exchange failed"
	}
}

// registeredGrantTypes reports the grants a registered client may actually use.
// Anything the client asked for beyond what this server implements is dropped:
// echoing it back would promise a grant that every token request then rejects.
func registeredGrantTypes(requested []string) []string {
	supported := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
		"urn:ietf:params:oauth:grant-type:token-exchange": true,
	}
	granted := make([]string, 0, len(requested))
	for _, grant := range requested {
		if supported[grant] && !contains(granted, grant) {
			granted = append(granted, grant)
		}
	}
	if len(granted) == 0 {
		// RFC 7591 section 2: authorization_code is the default, and this
		// server always issues a refresh token alongside it.
		return []string{"authorization_code", "refresh_token"}
	}
	return granted
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.Config.RegistrationEnabled {
		s.auditRegistrationFailure("registration_disabled", "")
		oauthError(w, http.StatusNotFound, "registration_disabled")
		return
	}
	var input struct {
		ClientName        string   `json:"client_name"`
		RedirectURIs      []string `json:"redirect_uris"`
		TokenEndpointAuth string   `json:"token_endpoint_auth_method"`
		GrantTypes        []string `json:"grant_types"`
		ResponseTypes     []string `json:"response_types"`
		Scope             string   `json:"scope"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || len(input.RedirectURIs) == 0 {
		s.auditRegistrationFailure("invalid_client_metadata", "")
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	for _, redirectURI := range input.RedirectURIs {
		if !validRedirect(redirectURI) {
			s.auditRegistrationFailure("invalid_redirect_uri", redirectURI)
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri")
			return
		}
		if len(s.Config.AllowedClientRedirectURIs) > 0 && !redirectAllowed(s.Config.AllowedClientRedirectURIs, redirectURI) {
			s.auditRegistrationFailure("redirect_uri_not_allowed", redirectURI)
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri")
			return
		}
	}
	clientID := "mcp_" + randomID()
	client := Client{ID: clientID, Name: input.ClientName, RedirectURIs: input.RedirectURIs, TokenEndpointAuth: input.TokenEndpointAuth, DynamicRegistration: true}

	// RFC 7591 section 3.2.1: the response is the full registered client
	// metadata, not just the identifier. A client that reads grant_types back
	// to decide whether it may refresh - rather than assuming - sees an empty
	// set and has to re-run the whole authorization dance every time.
	// Registration does not narrow what this server supports, so the echo
	// states the effective values rather than parroting the request.
	grantTypes := registeredGrantTypes(input.GrantTypes)
	responseTypes := []string{"code"}
	response := map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        s.now().Unix(),
		"client_name":                input.ClientName,
		"redirect_uris":              input.RedirectURIs,
		"token_endpoint_auth_method": input.TokenEndpointAuth,
		"grant_types":                grantTypes,
		"response_types":             responseTypes,
	}
	if scope := strings.TrimSpace(input.Scope); scope != "" {
		response["scope"] = scope
	} else if scopes := s.Config.supportedScopes(); len(scopes) > 0 {
		response["scope"] = strings.Join(scopes, " ")
	}
	if input.TokenEndpointAuth != "none" && input.TokenEndpointAuth != "" {
		secret := randomID()
		client.SecretHash = HashSecret(secret)
		response["client_secret"] = secret
	}
	if client.TokenEndpointAuth == "" {
		client.TokenEndpointAuth = "none"
		response["token_endpoint_auth_method"] = "none"
	}
	if err := s.Store.SaveClient(client); err != nil {
		s.auditRegistrationFailure("store_error", "")
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) auditRegistrationFailure(reason, redirectURI string) {
	attrs := map[string]any{"reason": reason}
	if redirectURI != "" {
		attrs["redirect_uri"] = redirectURI
	}
	s.Audit.Event("client_registration", "failure", attrs)
}

func (s *Server) auditAuthorizationFailure(request AuthorizationRequest, err error) {
	attrs := map[string]any{}
	if request.ClientID != "" {
		attrs["client_id"] = request.ClientID
	}
	if request.RedirectURI != "" {
		attrs["redirect_uri"] = request.RedirectURI
	}
	switch {
	case errors.Is(err, errUnknownClient):
		attrs["reason"] = "unregistered_client"
	default:
		var metadata *clientMetadataError
		if !errors.As(err, &metadata) {
			return
		}
		attrs["reason"] = "client_metadata_rejected"
	}
	s.Audit.Event("authorization_rejected", "failure", attrs)
}

// clientRedirectPermitted checks the redirect a client may use.
// A dynamically registered client is matched exactly against the URIs it
// registered. A Client ID Metadata Document is matched with the allowlist
// rules, including loopback port ignoring, and is also constrained by
// AllowedClientRedirectURIs when that list is set.
func (s *Server) clientRedirectPermitted(client Client, redirectURI string) bool {
	if isClientIDURL(client.ID) {
		if len(s.Config.AllowedClientRedirectURIs) > 0 && !redirectAllowed(s.Config.AllowedClientRedirectURIs, redirectURI) {
			return false
		}
		return redirectAllowed(client.RedirectURIs, redirectURI)
	}
	return contains(client.RedirectURIs, redirectURI)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.FormValue("token") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	_ = s.Store.RevokeRefreshToken(r.FormValue("token"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authenticateClient(r *http.Request) (Client, error) {
	if r.FormValue("client_assertion") != "" || r.FormValue("client_assertion_type") != "" {
		return s.authenticateClientAssertion(r)
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		clientID, secret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	if isClientIDURL(clientID) {
		client, err := s.fetchClientMetadata(r.Context(), clientID)
		if err != nil {
			return Client{}, err
		}
		return client, nil
	}
	client, err := s.Store.GetClient(clientID)
	if err != nil {
		return Client{}, err
	}
	if client.TokenEndpointAuth == "private_key_jwt" {
		return Client{}, errors.New("client is registered for private_key_jwt and must present a client_assertion")
	}
	if client.TokenEndpointAuth == "none" || client.SecretHash == "" {
		return client, nil
	}
	if subtle.ConstantTimeCompare([]byte(client.SecretHash), []byte(HashSecret(secret))) != 1 {
		return Client{}, errors.New("invalid client secret")
	}
	return client, nil
}

// authenticateClientAssertion implements the client authentication half of
// RFC 7523 private_key_jwt: the caller proves possession of a pre-registered
// private key instead of a shared secret. This is the resource-server
// authentication that the token-exchange grant previously skipped entirely.
func (s *Server) authenticateClientAssertion(r *http.Request) (Client, error) {
	if r.FormValue("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return Client{}, errors.New("unsupported client_assertion_type")
	}
	clientID := r.FormValue("client_id")
	if clientID == "" {
		return Client{}, errors.New("client_id is required with client_assertion")
	}
	client, err := s.Store.GetClient(clientID)
	if err != nil {
		return Client{}, err
	}
	if client.TokenEndpointAuth != "private_key_jwt" || client.PublicKeyPEM == "" {
		return Client{}, errors.New("client is not registered for private_key_jwt")
	}
	tokenEndpoint := s.Config.TokenEndpoint()
	algorithm := client.Algorithm
	if algorithm == "" {
		algorithm = "RS256"
	}
	claims, err := verifyClientAssertion(r.FormValue("client_assertion"), client.PublicKeyPEM, algorithm, clientID, tokenEndpoint)
	if err != nil {
		return Client{}, err
	}
	jti, _ := claims["jti"].(string)
	exp, _ := claims["exp"].(float64)
	if err := s.Store.ConsumeClientAssertionJTI(clientID, jti, time.Unix(int64(exp), 0)); err != nil {
		return Client{}, fmt.Errorf("client assertion rejected: %w", err)
	}
	return client, nil
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && contains(s.Config.TrustedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// httpsOnly refuses plaintext requests when the deployment requires TLS.
//
// X-Forwarded-Proto is set by the caller, so it is only evidence that TLS was
// terminated upstream when the deployment says a trusted proxy is the only way
// in — MCP_AUTH_TRUST_PROXY_TLS. Without that, honouring the header would let
// any caller that can reach this process satisfy RequireHTTPS by setting one
// header, which is no guard at all.
//
// Operators running behind an ingress that terminates TLS must set
// MCP_AUTH_TRUST_PROXY_TLS=true *and* ensure the proxy overwrites inbound
// X-Forwarded-* headers and is the only route to this process.
func (s *Server) httpsOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Config.RequireHTTPS || r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		if s.Config.TrustProxyTLS && r.Header.Get("X-Forwarded-Proto") == "https" {
			next.ServeHTTP(w, r)
			return
		}
		oauthErrorWithDescription(w, http.StatusBadRequest, "https_required",
			"this request arrived over plaintext HTTP; terminate TLS on this process, or set MCP_AUTH_TRUST_PROXY_TLS=true when a trusted proxy terminates it and is the only route in")
		return
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// oauthErrorWithDescription adds the RFC 6749 error_description. Use it where a
// bare code leaves the operator guessing at the cause.
func oauthErrorWithDescription(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
func redirectError(w http.ResponseWriter, r *http.Request, request AuthorizationRequest, code, description, issuer string, includeIssuer bool) {
	location, _ := url.Parse(request.RedirectURI)
	query := location.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if request.State != "" {
		query.Set("state", request.State)
	}
	if includeIssuer {
		query.Set("iss", issuer)
	}
	location.RawQuery = query.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}
func validPKCE(verifier, challenge string) bool {
	digest := sha256.Sum256([]byte(verifier))
	encoded := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(challenge)) == 1
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
