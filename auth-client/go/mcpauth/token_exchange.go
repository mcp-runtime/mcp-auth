package mcpauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type PrivateKeyJWTClientAuth struct {
	ClientID   string
	PrivateKey *rsa.PrivateKey
	KeyID      string
}

func (a PrivateKeyJWTClientAuth) Assertion(endpoint string) (string, error) {
	now := time.Now().Unix()
	header := b64JSON(map[string]any{"typ": "JWT", "alg": "RS256", "kid": a.KeyID})
	payload := b64JSON(map[string]any{"iss": a.ClientID, "sub": a.ClientID, "aud": endpoint, "iat": now, "exp": now + 300, "jti": randomString()})
	message := header + "." + payload
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type TokenExchangeClient struct {
	Endpoint   string
	HTTPClient *http.Client
	ClientAuth *PrivateKeyJWTClientAuth
	Cache      *TokenCache
	// AllowInsecure permits a non-https token endpoint. Leave it false so
	// subject tokens and client assertions are not posted over cleartext.
	AllowInsecure bool
	// RequestedTokenType defaults to the RFC 8693 access-token type. Set it to
	// request another issued type, such as a credential-access assertion.
	RequestedTokenType string
}

const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

// ExchangeError is returned when the token endpoint answers with a non-2xx
// status. It carries only the status, never the response body.
type ExchangeError struct{ Status int }

func (e *ExchangeError) Error() string { return fmt.Sprintf("token exchange returned %d", e.Status) }

var defaultExchangeClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: refuseRedirect}

func refuseRedirect(*http.Request, []*http.Request) error {
	return errors.New("token endpoint must not redirect")
}

func exchangeCacheKey(subjectToken, audience string, scopes []string) string {
	return exchangeCacheKeyFor(subjectToken, audience, scopes, accessTokenType)
}

func exchangeCacheKeyFor(subjectToken, audience string, scopes []string, requestedType string) string {
	sorted := append([]string(nil), scopes...)
	sort.Strings(sorted)
	material := subjectToken + "\x00" + audience + "\x00" + strings.Join(sorted, " ")
	if requestedType != accessTokenType {
		material += "\x00" + requestedType
	}
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (c *TokenExchangeClient) Exchange(subjectToken, audience string, scopes []string) (CachedToken, error) {
	return c.ExchangeContext(context.Background(), subjectToken, audience, scopes)
}

// ExchangeContext is Exchange with cancellation. A caller that must have every
// call authorised afresh (for example to honour session revocation) leaves
// Cache nil.
func (c *TokenExchangeClient) ExchangeContext(ctx context.Context, subjectToken, audience string, scopes []string) (CachedToken, error) {
	requestedType := c.RequestedTokenType
	if requestedType == "" {
		requestedType = accessTokenType
	}
	parsed, err := url.Parse(c.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return CachedToken{}, fmt.Errorf("token endpoint must be an absolute URL")
	}
	if parsed.Scheme != "https" && !c.AllowInsecure {
		return CachedToken{}, fmt.Errorf("token endpoint must use https")
	}
	key := exchangeCacheKeyFor(subjectToken, audience, scopes, requestedType)
	if c.Cache != nil {
		if token, ok := c.Cache.Get(key); ok {
			return token, nil
		}
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {subjectToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "requested_token_type": {requestedType}, "audience": {audience}, "scope": {strings.Join(scopes, " ")}}
	if c.ClientAuth != nil {
		assertion, err := c.ClientAuth.Assertion(c.Endpoint)
		if err != nil {
			return CachedToken{}, err
		}
		form.Set("client_id", c.ClientAuth.ClientID)
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	}
	client := c.HTTPClient
	if client == nil {
		client = defaultExchangeClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return CachedToken{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// 307 and 308 replay the body, so a redirect from an https endpoint to an
	// http one would post the subject token and client assertion in cleartext.
	// Refuse every redirect: a token endpoint has no reason to move. A caller
	// that set its own policy keeps it.
	if client.CheckRedirect == nil {
		copied := *client
		copied.CheckRedirect = refuseRedirect
		client = &copied
	}
	response, err := client.Do(request)
	if err != nil {
		return CachedToken{}, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return CachedToken{}, &ExchangeError{Status: response.StatusCode}
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.AccessToken == "" {
		return CachedToken{}, fmt.Errorf("invalid token exchange response")
	}
	token := CachedToken{AccessToken: result.AccessToken, TokenType: result.TokenType, Audience: audience, ExpiresAt: time.Now().Add(time.Duration(result.ExpiresIn) * time.Second), Scopes: strings.Fields(result.Scope)}
	if c.Cache != nil {
		c.Cache.Put(key, token)
	}
	return token, nil
}
func b64JSON(value map[string]any) string {
	encoded, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(encoded)
}
func randomString() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	return base64.RawURLEncoding.EncodeToString(value[:])
}
