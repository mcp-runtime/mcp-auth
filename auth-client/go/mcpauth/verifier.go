package mcpauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrInvalidToken = errors.New("invalid MCP access token")

const (
	defaultJWKSCacheTTL  = 5 * time.Minute
	defaultJWKSMinFetch  = 30 * time.Second
	defaultUnknownKeyTTL = 30 * time.Second
	defaultClockSkew     = 60 * time.Second
	maxJWKSBody          = 1 << 20
)

type TokenClaims struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   map[string]bool
	Raw      map[string]any
}

type JWTVerifier struct {
	JWKSURL        string
	Issuer         string
	Audience       string
	Algorithms     map[string]bool
	RequiredScopes map[string]bool
	HTTPClient     *http.Client
	ClockSkew      time.Duration
	JWKSCacheTTL   time.Duration
	JWKSMinFetch   time.Duration
	UnknownKeyTTL  time.Duration
	// TokenTypes lists the accepted JOSE "typ" values. Empty accepts "JWT" and
	// "at+jwt". RequireType rejects tokens that carry no typ at all, so a
	// verifier for a non-access token type cannot be satisfied by an untyped JWT.
	TokenTypes  []string
	RequireType bool

	mu          sync.RWMutex
	refreshMu   sync.Mutex
	keys        map[string]*rsa.PublicKey
	loadedAt    time.Time
	lastRefresh time.Time
	unknownKeys map[string]time.Time
}

// Verify validates a token using a background context. Call VerifyContext when
// verification is part of an HTTP request and cancellation must propagate.
func (v *JWTVerifier) Verify(token string) (TokenClaims, error) {
	return v.VerifyContext(context.Background(), token)
}

func (v *JWTVerifier) VerifyContext(ctx context.Context, token string) (TokenClaims, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return TokenClaims{}, ErrInvalidToken
	}
	var header map[string]any
	var claims map[string]any
	if err := decodeJSON(parts[0], &header); err != nil {
		return TokenClaims{}, ErrInvalidToken
	}
	if err := decodeJSON(parts[1], &claims); err != nil {
		return TokenClaims{}, ErrInvalidToken
	}
	algorithm, ok := header["alg"].(string)
	if !ok || !v.allowedAlgorithm(algorithm) {
		return TokenClaims{}, fmt.Errorf("%w: algorithm", ErrInvalidToken)
	}
	// A present typ must be a string: a number, array, or object is not one of
	// the allowed values, so type-asserting and ignoring the failure let it
	// through unchecked.
	raw, present := header["typ"]
	if !present && v.RequireType {
		return TokenClaims{}, fmt.Errorf("%w: typ", ErrInvalidToken)
	}
	if present {
		typ, ok := raw.(string)
		if !ok || !v.allowedType(typ) {
			return TokenClaims{}, fmt.Errorf("%w: typ", ErrInvalidToken)
		}
	}
	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return TokenClaims{}, fmt.Errorf("%w: kid", ErrInvalidToken)
	}
	key, err := v.ensureKeys(ctx, kid, algorithm)
	if err != nil {
		return TokenClaims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || key == nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return TokenClaims{}, fmt.Errorf("%w: signature", ErrInvalidToken)
	}
	skew := v.ClockSkew
	if skew <= 0 {
		skew = defaultClockSkew
	}
	if claims["iss"] != v.Issuer || !validTime(claims["exp"], skew) || !notBeforeValid(claims["nbf"], skew) || !audienceContains(claims["aud"], v.Audience) {
		return TokenClaims{}, ErrInvalidToken
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return TokenClaims{}, ErrInvalidToken
	}
	scopes := map[string]bool{}
	if scope, ok := claims["scope"].(string); ok {
		for _, value := range strings.Fields(scope) {
			scopes[value] = true
		}
	}
	for required := range v.RequiredScopes {
		if !scopes[required] {
			return TokenClaims{}, fmt.Errorf("%w: scope", ErrInvalidToken)
		}
	}
	return TokenClaims{Subject: subject, Issuer: v.Issuer, Audience: audienceValues(claims["aud"]), Scopes: scopes, Raw: claims}, nil
}

func (v *JWTVerifier) allowedType(typ string) bool {
	if len(v.TokenTypes) == 0 {
		return typ == "JWT" || typ == "at+jwt"
	}
	for _, allowed := range v.TokenTypes {
		if typ == allowed {
			return true
		}
	}
	return false
}

func (v *JWTVerifier) allowedAlgorithm(value string) bool {
	if len(v.Algorithms) == 0 {
		return value == "RS256"
	}
	return v.Algorithms[value] && value == "RS256"
}

func validTime(value any, skew time.Duration) bool {
	number, ok := value.(float64)
	return ok && time.Now().Before(time.Unix(int64(number), 0).Add(skew))
}

func notBeforeValid(value any, skew time.Duration) bool {
	if value == nil {
		return true
	}
	number, ok := value.(float64)
	return ok && !time.Unix(int64(number), 0).After(time.Now().Add(skew))
}

func audienceContains(value any, expected string) bool {
	for _, item := range audienceValues(value) {
		if item == expected {
			return true
		}
	}
	return false
}

func audienceValues(value any) []string {
	switch item := value.(type) {
	case string:
		return []string{item}
	case []any:
		values := []string{}
		for _, candidate := range item {
			if text, ok := candidate.(string); ok {
				values = append(values, text)
			}
		}
		return values
	}
	return nil
}

func decodeJSON(value string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, target)
}

func (v *JWTVerifier) ensureKeys(ctx context.Context, kid, algorithm string) (*rsa.PublicKey, error) {
	cacheTTL := v.JWKSCacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultJWKSCacheTTL
	}
	minFetch := v.JWKSMinFetch
	if minFetch <= 0 {
		minFetch = defaultJWKSMinFetch
	}
	unknownTTL := v.UnknownKeyTTL
	if unknownTTL <= 0 {
		unknownTTL = defaultUnknownKeyTTL
	}
	v.mu.RLock()
	key := v.keys[kid]
	fresh := len(v.keys) > 0 && time.Since(v.loadedAt) < cacheTTL
	negative := time.Since(v.unknownKeys[kid]) < unknownTTL
	lastRefresh := v.lastRefresh
	v.mu.RUnlock()
	if key != nil && fresh {
		return key, nil
	}
	if negative && time.Since(lastRefresh) < minFetch {
		return nil, fmt.Errorf("%w: key not found", ErrInvalidToken)
	}
	if v.JWKSURL == "" {
		return nil, fmt.Errorf("%w: JWKS unavailable", ErrInvalidToken)
	}
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	v.mu.RLock()
	key = v.keys[kid]
	fresh = len(v.keys) > 0 && time.Since(v.loadedAt) < cacheTTL
	lastRefresh = v.lastRefresh
	v.mu.RUnlock()
	if key != nil && fresh {
		return key, nil
	}
	if time.Since(lastRefresh) < minFetch {
		return nil, fmt.Errorf("%w: key not found", ErrInvalidToken)
	}
	client := v.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS request", ErrInvalidToken)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS request", ErrInvalidToken)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: JWKS status", ErrInvalidToken)
	}
	var raw struct {
		Keys []map[string]string `json:"keys"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS read", ErrInvalidToken)
	}
	if len(body) > maxJWKSBody {
		return nil, fmt.Errorf("%w: JWKS too large", ErrInvalidToken)
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: JWKS JSON", ErrInvalidToken)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range raw.Keys {
		if jwk["kty"] != "RSA" || (jwk["use"] != "" && jwk["use"] != "sig") || (jwk["alg"] != "" && jwk["alg"] != algorithm) {
			continue
		}
		modulus, errN := base64.RawURLEncoding.DecodeString(jwk["n"])
		exponent, errE := base64.RawURLEncoding.DecodeString(jwk["e"])
		if errN != nil || errE != nil || len(modulus) == 0 || len(exponent) == 0 || jwk["kid"] == "" {
			continue
		}
		e := 0
		for _, value := range exponent {
			e = e*256 + int(value)
		}
		if e == 0 {
			continue
		}
		keys[jwk["kid"]] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}
	}
	now := time.Now()
	v.mu.Lock()
	v.keys, v.loadedAt, v.lastRefresh = keys, now, now
	if v.unknownKeys == nil {
		v.unknownKeys = map[string]time.Time{}
	}
	if _, found := keys[kid]; !found {
		v.unknownKeys[kid] = now
	} else {
		delete(v.unknownKeys, kid)
	}
	key = keys[kid]
	v.mu.Unlock()
	if key == nil {
		return nil, fmt.Errorf("%w: key not found", ErrInvalidToken)
	}
	return key, nil
}
