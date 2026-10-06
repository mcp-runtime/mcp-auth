package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore is a durable single-node Store implementation. It stores only
// hashes for bearer values and uses transactions for one-time consumption.
// Deployments with multiple auth-server replicas should use a shared database
// or provide a Store implementation backed by their enterprise database.
type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(databaseURL string) (*SQLiteStore, error) {
	if databaseURL == "" {
		return nil, errors.New("sqlite database URL is required")
	}
	db, err := sql.Open("sqlite", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	store := &SQLiteStore{db: db}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure sqlite store: %w", err)
	}
	if err := store.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// currentSchemaVersion is tracked via PRAGMA user_version. Bump it and add an
// entry to migrations whenever the schema changes, so upgrading over an
// existing database file applies exactly the missing ALTER/CREATE statements
// instead of relying on CREATE TABLE IF NOT EXISTS, which silently no-ops on
// a table that already exists in its old shape.
const currentSchemaVersion = 6

// migrations[v] takes a database at schema version v to v+1. Statements must
// be additive and safe to run inside a single transaction alongside the
// PRAGMA user_version update that follows them.
var migrations = map[int]string{
	0: `
ALTER TABLE clients ADD COLUMN public_key_pem TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS client_assertions (
  client_id TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, jti)
);
ALTER TABLE consent_requests ADD COLUMN code_verifier TEXT NOT NULL DEFAULT '';`,
	1: `
CREATE TABLE IF NOT EXISTS upstream_sessions (
  subject TEXT PRIMARY KEY, access_token TEXT NOT NULL, refresh_token TEXT NOT NULL,
  token_type TEXT NOT NULL, expires_at INTEGER NOT NULL, scope TEXT NOT NULL
);`,
	2: `ALTER TABLE clients ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'RS256';`,
	3: `ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT '';`,
	4: `ALTER TABLE clients ADD COLUMN dynamic_registration INTEGER NOT NULL DEFAULT 0;
-- Every interactive client in a pre-migration database was created through
-- POST /register, so its name is application-supplied. Backfilling 0 would
-- present those names on the consent page without the unverified label,
-- implying this server had verified them. Mark them dynamic and let startup
-- rewrite the operator-provisioned ones: loadResourceClients saves its
-- clients with DynamicRegistration false on every boot.
UPDATE clients SET dynamic_registration = 1;`,
	5: `ALTER TABLE clients ADD COLUMN resource TEXT NOT NULL DEFAULT '';`,
}

const freshSchema = `
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
  token_endpoint_auth TEXT NOT NULL, secret_hash TEXT NOT NULL, public_key_pem TEXT NOT NULL DEFAULT '',
  algorithm TEXT NOT NULL DEFAULT 'RS256', dynamic_registration INTEGER NOT NULL DEFAULT 0,
  resource TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS client_assertions (
  client_id TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, jti)
);
CREATE TABLE IF NOT EXISTS authorization_codes (
  value_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
  subject TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  value_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL, subject TEXT NOT NULL,
  scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL, revoked INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS consent_requests (
  value_hash TEXT PRIMARY KEY, request_json TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
  code_verifier TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS upstream_sessions (
  subject TEXT PRIMARY KEY, access_token TEXT NOT NULL, refresh_token TEXT NOT NULL,
  token_type TEXT NOT NULL, expires_at INTEGER NOT NULL, scope TEXT NOT NULL
);`

func (s *SQLiteStore) initialize() error {
	var exists int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='clients'`).Scan(&exists); err != nil {
		return fmt.Errorf("inspect sqlite schema: %w", err)
	}
	if exists == 0 {
		if _, err := s.db.Exec(freshSchema); err != nil {
			return fmt.Errorf("initialize sqlite store: %w", err)
		}
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion)); err != nil {
			return fmt.Errorf("set sqlite schema version: %w", err)
		}
		return nil
	}
	return s.migrate()
}

func (s *SQLiteStore) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read sqlite schema version: %w", err)
	}
	if version >= currentSchemaVersion {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for v := version; v < currentSchemaVersion; v++ {
		statement, ok := migrations[v]
		if !ok {
			return fmt.Errorf("no migration registered from schema version %d", v)
		}
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply migration from schema version %d: %w", v, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion)); err != nil {
		return fmt.Errorf("set sqlite schema version: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) SaveClient(client Client) error {
	redirects, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}
	algorithm := client.Algorithm
	if algorithm == "" {
		algorithm = "RS256"
	}
	dynamic := 0
	if client.DynamicRegistration {
		dynamic = 1
	}
	_, err = s.db.Exec(`INSERT INTO clients (id,name,redirect_uris,token_endpoint_auth,secret_hash,public_key_pem,algorithm,dynamic_registration,resource)
VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, redirect_uris=excluded.redirect_uris,
token_endpoint_auth=excluded.token_endpoint_auth, secret_hash=excluded.secret_hash, public_key_pem=excluded.public_key_pem,
algorithm=excluded.algorithm, dynamic_registration=excluded.dynamic_registration, resource=excluded.resource`,
		client.ID, client.Name, string(redirects), client.TokenEndpointAuth, client.SecretHash, client.PublicKeyPEM, algorithm, dynamic, client.Resource)
	return err
}

func (s *SQLiteStore) GetClient(id string) (Client, error) {
	var client Client
	var redirects string
	var dynamic int
	err := s.db.QueryRow(`SELECT id,name,redirect_uris,token_endpoint_auth,secret_hash,public_key_pem,algorithm,dynamic_registration,resource FROM clients WHERE id=?`, id).
		Scan(&client.ID, &client.Name, &redirects, &client.TokenEndpointAuth, &client.SecretHash, &client.PublicKeyPEM, &client.Algorithm, &dynamic, &client.Resource)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	if err := json.Unmarshal([]byte(redirects), &client.RedirectURIs); err != nil {
		return Client{}, fmt.Errorf("decode client redirect URIs: %w", err)
	}
	client.DynamicRegistration = dynamic != 0
	return client, nil
}

func (s *SQLiteStore) ConsumeClientAssertionJTI(clientID, jti string, expiresAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM client_assertions WHERE expires_at < ?`, time.Now().UnixNano()); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO client_assertions (client_id,jti,expires_at) VALUES (?,?,?)`, clientID, jti, expiresAt.UnixNano()); err != nil {
		return ErrAlreadyUsed
	}
	return tx.Commit()
}

func (s *SQLiteStore) SaveAuthorizationCode(code AuthorizationCode) error {
	scope, err := json.Marshal(code.Scope)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO authorization_codes
(value_hash,client_id,redirect_uri,code_challenge,scope,resource,subject,nonce,expires_at,used)
VALUES (?,?,?,?,?,?,?,?,?,?)`, code.ValueHash, code.ClientID, code.RedirectURI, code.CodeChallenge,
		string(scope), code.Resource, code.Subject, code.Nonce, code.ExpiresAt.UnixNano(), boolInt(code.Used))
	return err
}

func (s *SQLiteStore) ConsumeAuthorizationCode(value string, now time.Time) (AuthorizationCode, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return AuthorizationCode{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var code AuthorizationCode
	var scope string
	var expires int64
	var used int
	err = tx.QueryRow(`SELECT client_id,redirect_uri,code_challenge,scope,resource,subject,nonce,expires_at,used
FROM authorization_codes WHERE value_hash=?`, HashSecret(value)).Scan(&code.ClientID, &code.RedirectURI,
		&code.CodeChallenge, &scope, &code.Resource, &code.Subject, &code.Nonce, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorizationCode{}, ErrNotFound
	}
	if err != nil {
		return AuthorizationCode{}, err
	}
	code.ValueHash, code.ExpiresAt, code.Used = HashSecret(value), time.Unix(0, expires), used != 0
	if code.ExpiresAt.Before(now) {
		return AuthorizationCode{}, ErrNotFound
	}
	if code.Used {
		return AuthorizationCode{}, ErrAlreadyUsed
	}
	if err := json.Unmarshal([]byte(scope), &code.Scope); err != nil {
		return AuthorizationCode{}, err
	}
	if _, err := tx.Exec(`UPDATE authorization_codes SET used=1 WHERE value_hash=? AND used=0`, code.ValueHash); err != nil {
		return AuthorizationCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationCode{}, err
	}
	code.Used = true
	return code, nil
}

func (s *SQLiteStore) SaveRefreshToken(token RefreshToken) error {
	scope, err := json.Marshal(token.Scope)
	if err != nil {
		return err
	}
	result, err := s.db.Exec(`INSERT OR REPLACE INTO refresh_tokens
(value_hash,family_id,client_id,subject,scope,resource,expires_at,used,revoked)
SELECT ?,?,?,?,?,?,?,?,? WHERE ?='' OR NOT EXISTS
(SELECT 1 FROM refresh_tokens WHERE family_id=? AND revoked=1)`,
		token.ValueHash, token.FamilyID, token.ClientID, token.Subject, string(scope), token.Resource, token.ExpiresAt.UnixNano(),
		boolInt(token.Used), boolInt(token.Revoked), token.FamilyID, token.FamilyID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrRefreshRevoked
	}
	return nil
}

func (s *SQLiteStore) ConsumeRefreshToken(value string, now time.Time) (RefreshToken, error) {
	return s.consumeRefreshToken(value, "", now)
}

func (s *SQLiteStore) ConsumeRefreshTokenForClient(value, clientID string, now time.Time) (RefreshToken, error) {
	if clientID == "" {
		return RefreshToken{}, ErrRefreshClientMismatch
	}
	return s.consumeRefreshToken(value, clientID, now)
}

func (s *SQLiteStore) consumeRefreshToken(value, clientID string, now time.Time) (RefreshToken, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return RefreshToken{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var token RefreshToken
	var scope string
	var expires int64
	var used, revoked int
	err = tx.QueryRow(`SELECT family_id,client_id,subject,scope,resource,expires_at,used,revoked
FROM refresh_tokens WHERE value_hash=?`, HashSecret(value)).Scan(&token.FamilyID, &token.ClientID, &token.Subject, &scope,
		&token.Resource, &expires, &used, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, err
	}
	token.ValueHash, token.ExpiresAt = HashSecret(value), time.Unix(0, expires)
	token.Used, token.Revoked = used != 0, revoked != 0
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
	if err := json.Unmarshal([]byte(scope), &token.Scope); err != nil {
		return RefreshToken{}, err
	}
	if _, err := tx.Exec(`UPDATE refresh_tokens SET used=1 WHERE value_hash=? AND used=0 AND revoked=0`, token.ValueHash); err != nil {
		return RefreshToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return RefreshToken{}, err
	}
	token.Used = true
	return token, nil
}

func (s *SQLiteStore) RevokeRefreshToken(value string) error {
	result, err := s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE value_hash=?`, HashSecret(value))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) RevokeRefreshFamily(value string) error {
	var familyID string
	if err := s.db.QueryRow(`SELECT family_id FROM refresh_tokens WHERE value_hash=?`, HashSecret(value)).Scan(&familyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if familyID == "" {
		_, err := s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE value_hash=?`, HashSecret(value))
		return err
	}
	_, err := s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE family_id=?`, familyID)
	return err
}

func (s *SQLiteStore) SaveConsentRequest(request ConsentRequest) error {
	data, err := json.Marshal(request.Request)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO consent_requests (value_hash,request_json,nonce,expires_at,code_verifier)
VALUES (?,?,?,?,?)`, request.ValueHash, string(data), request.Nonce, request.ExpiresAt.UnixNano(), request.CodeVerifier)
	return err
}

func (s *SQLiteStore) ConsumeConsentRequest(value string, now time.Time) (ConsentRequest, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return ConsentRequest{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var request ConsentRequest
	var data string
	var expires int64
	err = tx.QueryRow(`SELECT request_json,nonce,expires_at,code_verifier FROM consent_requests WHERE value_hash=?`, HashSecret(value)).
		Scan(&data, &request.Nonce, &expires, &request.CodeVerifier)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsentRequest{}, ErrNotFound
	}
	if err != nil {
		return ConsentRequest{}, err
	}
	request.ValueHash, request.ExpiresAt = HashSecret(value), time.Unix(0, expires)
	if request.ExpiresAt.Before(now) {
		return ConsentRequest{}, ErrNotFound
	}
	if err := json.Unmarshal([]byte(data), &request.Request); err != nil {
		return ConsentRequest{}, err
	}
	if _, err := tx.Exec(`DELETE FROM consent_requests WHERE value_hash=?`, request.ValueHash); err != nil {
		return ConsentRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConsentRequest{}, err
	}
	return request, nil
}

func (s *SQLiteStore) SaveUpstreamSession(subject string, session UpstreamSession) error {
	scope, err := json.Marshal(session.Scope)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO upstream_sessions (subject,access_token,refresh_token,token_type,expires_at,scope)
VALUES (?,?,?,?,?,?) ON CONFLICT(subject) DO UPDATE SET access_token=excluded.access_token,
refresh_token=excluded.refresh_token, token_type=excluded.token_type, expires_at=excluded.expires_at, scope=excluded.scope`,
		subject, session.AccessToken, session.RefreshToken, session.TokenType, session.ExpiresAt.UnixNano(), string(scope))
	return err
}

func (s *SQLiteStore) GetUpstreamSession(subject string) (UpstreamSession, error) {
	var session UpstreamSession
	var expires int64
	var scope string
	err := s.db.QueryRow(`SELECT access_token,refresh_token,token_type,expires_at,scope FROM upstream_sessions WHERE subject=?`, subject).
		Scan(&session.AccessToken, &session.RefreshToken, &session.TokenType, &expires, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		return UpstreamSession{}, ErrNotFound
	}
	if err != nil {
		return UpstreamSession{}, err
	}
	session.ExpiresAt = time.Unix(0, expires)
	if err := json.Unmarshal([]byte(scope), &session.Scope); err != nil {
		return UpstreamSession{}, err
	}
	return session, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
