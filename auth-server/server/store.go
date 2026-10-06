package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrNotFound = errors.New("record not found")
var ErrAlreadyUsed = errors.New("record already used")
var ErrRefreshExpired = fmt.Errorf("refresh expired: %w", ErrNotFound)
var ErrRefreshRevoked = fmt.Errorf("refresh revoked: %w", ErrNotFound)
var ErrRefreshClientMismatch = errors.New("refresh client mismatch")

type Client struct {
	ID                string
	Name              string
	RedirectURIs      []string
	TokenEndpointAuth string
	SecretHash        string
	// DynamicRegistration is true for clients created by POST /register.
	// Their client_name was supplied by the application and has not been
	// verified, so the consent page says so. Operator-provisioned clients
	// leave this false.
	DynamicRegistration bool
	// PublicKeyPEM holds an RSA or EC public key (PKIX, PEM-encoded) for
	// clients registered with TokenEndpointAuth "private_key_jwt". It is
	// never secret.
	PublicKeyPEM string
	// Algorithm is the JWS algorithm this client's client_assertion must be
	// signed with: "RS256" (default), "PS256", or "ES256". The assertion's
	// own header must match this exactly rather than any allowed value, so a
	// client can't switch algorithms without re-registering its key.
	Algorithm string
}

type AuthorizationCode struct {
	ValueHash     string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Scope         []string
	Resource      string
	Subject       string
	Nonce         string
	ExpiresAt     time.Time
	Used          bool
}

type RefreshToken struct {
	ValueHash string
	FamilyID  string
	ClientID  string
	Subject   string
	Scope     []string
	Resource  string
	ExpiresAt time.Time
	Used      bool
	Revoked   bool
}

type ConsentRequest struct {
	ValueHash string
	Request   AuthorizationRequest
	Nonce     string
	ExpiresAt time.Time
	// CodeVerifier is this server's own PKCE verifier for the upstream OIDC
	// authorization request, set once Begin() has produced it. It lives here
	// instead of an in-process map so it expires with the rest of the pending
	// request and is visible to whichever replica handles the callback.
	CodeVerifier string
}

// UpstreamSession is the token set an upstream OIDC provider issued at
// login, kept so the "upstream_session" downstream-token strategy can reuse
// (and refresh) it instead of requiring RFC 8693 token-exchange support from
// the upstream provider. Unlike the local refresh tokens above, this holds a
// live, directly usable secret rather than a hash: a deployment's Store
// backend must be chosen with that in mind (see docs/auth-server.md).
type UpstreamSession struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	Scope        []string
}

type Store interface {
	SaveClient(Client) error
	GetClient(string) (Client, error)
	SaveAuthorizationCode(AuthorizationCode) error
	ConsumeAuthorizationCode(string, time.Time) (AuthorizationCode, error)
	SaveRefreshToken(RefreshToken) error
	ConsumeRefreshToken(string, time.Time) (RefreshToken, error)
	// Bind the authenticated client before mutation or replay classification.
	ConsumeRefreshTokenForClient(string, string, time.Time) (RefreshToken, error)
	RevokeRefreshToken(string) error
	RevokeRefreshFamily(string) error
	SaveConsentRequest(ConsentRequest) error
	ConsumeConsentRequest(string, time.Time) (ConsentRequest, error)
	// ConsumeClientAssertionJTI records a client_assertion's (client_id, jti)
	// pair as used, returning ErrAlreadyUsed if it was already consumed while
	// still valid. This bounds RFC 7523 private_key_jwt replay to a single use
	// per assertion, regardless of the assertion's own short lifetime.
	ConsumeClientAssertionJTI(clientID, jti string, expiresAt time.Time) error
	// SaveUpstreamSession and GetUpstreamSession persist the upstream token
	// set for the "upstream_session" downstream-token strategy, keyed by the
	// local subject. There is one session per subject: a new login overwrites
	// the previous one.
	SaveUpstreamSession(subject string, session UpstreamSession) error
	GetUpstreamSession(subject string) (UpstreamSession, error)
}

type MemoryStore struct {
	mu               sync.Mutex
	clients          map[string]Client
	codes            map[string]AuthorizationCode
	refresh          map[string]RefreshToken
	consent          map[string]ConsentRequest
	assertions       map[string]time.Time
	upstreamSessions map[string]UpstreamSession
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{clients: map[string]Client{}, codes: map[string]AuthorizationCode{}, refresh: map[string]RefreshToken{}, consent: map[string]ConsentRequest{}, assertions: map[string]time.Time{}, upstreamSessions: map[string]UpstreamSession{}}
}

func HashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *MemoryStore) SaveClient(client Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.ID] = client
	return nil
}

func (s *MemoryStore) ConsumeClientAssertionJTI(clientID, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, expiry := range s.assertions {
		if expiry.Before(now) {
			delete(s.assertions, key)
		}
	}
	key := clientID + "|" + jti
	if expiry, ok := s.assertions[key]; ok && expiry.After(now) {
		return ErrAlreadyUsed
	}
	s.assertions[key] = expiresAt
	return nil
}

func (s *MemoryStore) GetClient(id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	return client, nil
}

func (s *MemoryStore) SaveAuthorizationCode(code AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.ValueHash] = code
	return nil
}

func (s *MemoryStore) ConsumeAuthorizationCode(value string, now time.Time) (AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	code, ok := s.codes[hash]
	if !ok || code.ExpiresAt.Before(now) {
		return AuthorizationCode{}, ErrNotFound
	}
	if code.Used {
		return AuthorizationCode{}, ErrAlreadyUsed
	}
	code.Used = true
	s.codes[hash] = code
	return code, nil
}

func (s *MemoryStore) SaveRefreshToken(token RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.refresh {
		if token.FamilyID != "" && existing.FamilyID == token.FamilyID && existing.Revoked {
			return ErrRefreshRevoked
		}
	}
	s.refresh[token.ValueHash] = token
	return nil
}

func (s *MemoryStore) ConsumeRefreshToken(value string, now time.Time) (RefreshToken, error) {
	return s.consumeRefreshToken(value, "", now)
}

func (s *MemoryStore) ConsumeRefreshTokenForClient(value, clientID string, now time.Time) (RefreshToken, error) {
	if clientID == "" {
		return RefreshToken{}, ErrRefreshClientMismatch
	}
	return s.consumeRefreshToken(value, clientID, now)
}

func (s *MemoryStore) consumeRefreshToken(value, clientID string, now time.Time) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	token, ok := s.refresh[hash]
	if !ok {
		return RefreshToken{}, ErrNotFound
	}
	if clientID != "" && token.ClientID != clientID {
		return token, ErrRefreshClientMismatch
	}
	if token.Revoked {
		return token, ErrRefreshRevoked
	}
	if !token.ExpiresAt.After(now) {
		return token, ErrRefreshExpired
	}
	if token.Used {
		return token, ErrAlreadyUsed
	}
	token.Used = true
	s.refresh[hash] = token
	return token, nil
}

func (s *MemoryStore) RevokeRefreshToken(value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	token, ok := s.refresh[hash]
	if !ok {
		return ErrNotFound
	}
	token.Revoked = true
	s.refresh[hash] = token
	return nil
}

func (s *MemoryStore) RevokeRefreshFamily(value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	token, ok := s.refresh[hash]
	if !ok {
		return ErrNotFound
	}
	if token.FamilyID == "" {
		token.Revoked = true
		s.refresh[hash] = token
		return nil
	}
	for key, candidate := range s.refresh {
		if candidate.FamilyID == token.FamilyID {
			candidate.Revoked = true
			s.refresh[key] = candidate
		}
	}
	return nil
}

func (s *MemoryStore) SaveConsentRequest(request ConsentRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consent[request.ValueHash] = request
	return nil
}

func (s *MemoryStore) ConsumeConsentRequest(value string, now time.Time) (ConsentRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	request, ok := s.consent[hash]
	if !ok || request.ExpiresAt.Before(now) {
		return ConsentRequest{}, ErrNotFound
	}
	delete(s.consent, hash)
	return request, nil
}

func (s *MemoryStore) SaveUpstreamSession(subject string, session UpstreamSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreamSessions[subject] = session
	return nil
}

func (s *MemoryStore) GetUpstreamSession(subject string) (UpstreamSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.upstreamSessions[subject]
	if !ok {
		return UpstreamSession{}, ErrNotFound
	}
	return session, nil
}
