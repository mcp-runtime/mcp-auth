package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

type KeyManager struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
}

func NewKeyManager(path string) (*KeyManager, error) {
	if path == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate local signing key: %w", err)
		}
		return &KeyManager{PrivateKey: key, KeyID: keyThumbprint(key)}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key is not PEM encoded")
	}
	var key *rsa.PrivateKey
	if parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	} else if parsed, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		key = parsed
	}
	if key == nil {
		return nil, errors.New("signing key is not an RSA private key")
	}
	return &KeyManager{PrivateKey: key, KeyID: keyThumbprint(key)}, nil
}

func (k *KeyManager) JWKS() map[string]any {
	public := k.PrivateKey.PublicKey
	return map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.KeyID,
		"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}}
}

func (k *KeyManager) Sign(issuer, subject, resource string, scopes []string, ttl time.Duration, nonce string) (string, error) {
	return k.signClaims("at+jwt", baseClaims(issuer, subject, resource, scopes, ttl, nonce, ""))
}

func baseClaims(issuer, subject, resource string, scopes []string, ttl time.Duration, nonce, sessionID string) map[string]any {
	now := time.Now().UTC()
	claims := map[string]any{"iss": issuer, "sub": subject, "aud": resource, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": randomID(), "scope": joinScopes(scopes)}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if sessionID != "" {
		claims["sid"] = sessionID
	}
	return claims
}

func (k *KeyManager) signClaims(typ string, claims map[string]any) (string, error) {
	header := map[string]any{"typ": typ, "alg": "RS256", "kid": k.KeyID}
	headEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(header))
	claimEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	message := []byte(headEncoded + "." + claimEncoded)
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, k.PrivateKey, cryptoHashSHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return string(message) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Verify checks a token signed by this key manager's own private key and
// returns its claims. It is used to confirm that a subject_token presented to
// the token-exchange grant was actually issued by this server, rather than
// relaying an arbitrary caller-supplied string upstream.
func (k *KeyManager) Verify(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is malformed")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("token header is malformed")
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "RS256" || header.KeyID != k.KeyID {
		return nil, errors.New("token algorithm or key is invalid")
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("token claims are malformed")
	}
	var claims map[string]any
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return nil, errors.New("token claims are invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("token signature is malformed")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&k.PrivateKey.PublicKey, cryptoHashSHA256, digest[:], signature) != nil {
		return nil, errors.New("token signature is invalid")
	}
	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().After(time.Unix(int64(exp), 0)) {
		return nil, errors.New("token is expired")
	}
	return claims, nil
}

// Kept as a named value to make the signing primitive explicit in audits.
var cryptoHashSHA256 = cryptoHash()

func cryptoHash() crypto.Hash { return crypto.SHA256 }

func randomID() string {
	var value [24]byte
	_, _ = rand.Read(value[:])
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

func keyThumbprint(key *rsa.PrivateKey) string {
	public := key.PublicKey
	canonical := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		base64.RawURLEncoding.EncodeToString(public.N.Bytes()))
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
