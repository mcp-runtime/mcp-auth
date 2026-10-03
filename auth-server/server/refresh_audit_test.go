package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func refreshStores(t *testing.T) map[string]Store {
	t.Helper()
	sqlite, err := NewSQLiteStore(filepath.Join(t.TempDir(), "refresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlite.Close() })
	return map[string]Store{"memory": NewMemoryStore(), "sqlite": sqlite}
}

func TestRefreshClientBindingAndRevocationRace(t *testing.T) {
	for name, store := range refreshStores(t) {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			old := RefreshToken{ValueHash: HashSecret("old-secret"), FamilyID: "opaque-family", ClientID: "owner", Resource: "https://mcp.example.com/buddy/mcp", ExpiresAt: now.Add(time.Hour)}
			if err := store.SaveRefreshToken(old); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ConsumeRefreshTokenForClient("old-secret", "other", now); !errors.Is(err, ErrRefreshClientMismatch) {
				t.Fatalf("wrong client consumed: %v", err)
			}
			if _, err := store.ConsumeRefreshTokenForClient("old-secret", "owner", now); err != nil {
				t.Fatalf("owner credential damaged by mismatch: %v", err)
			}
			if _, err := store.ConsumeRefreshTokenForClient("old-secret", "other", now); !errors.Is(err, ErrRefreshClientMismatch) {
				t.Fatalf("wrong client could trigger replay revocation: %v", err)
			}
			if _, err := store.ConsumeRefreshTokenForClient("old-secret", "owner", now); !errors.Is(err, ErrAlreadyUsed) {
				t.Fatalf("replay defense missing: %v", err)
			}
			if err := store.RevokeRefreshFamily("old-secret"); err != nil {
				t.Fatal(err)
			}
			// Interleaving: a winning refresh consumed old, replay revoked the family,
			// then that refresh attempted to persist a descendant. It must not revive it.
			old.ValueHash = HashSecret("late-descendant")
			old.Used = false
			if err := store.SaveRefreshToken(old); !errors.Is(err, ErrRefreshRevoked) {
				t.Fatalf("revoked family revived: %v", err)
			}
		})
	}
}

func TestRefreshAuditReasonsCorrelationAndRedaction(t *testing.T) {
	for _, reason := range []string{"unknown", "expired", "revoked", "replay", "client_mismatch", "rotated"} {
		t.Run(reason, func(t *testing.T) {
			s := testServer(t)
			var output bytes.Buffer
			s.Audit = NewAuditLogger(&output)
			if err := s.Store.SaveClient(Client{ID: "other", TokenEndpointAuth: "none"}); err != nil {
				t.Fatal(err)
			}
			raw := "never-log-this-refresh"
			token := RefreshToken{ValueHash: HashSecret(raw), FamilyID: "opaque-family", ClientID: "client", Scope: []string{"tools:read"}, Resource: s.Config.Resource, ExpiresAt: time.Now().Add(time.Hour)}
			switch reason {
			case "expired":
				token.ExpiresAt = time.Now().Add(-time.Hour)
			case "revoked":
				token.Revoked = true
			case "replay":
				token.Used = true
			}
			if reason != "unknown" {
				if err := s.Store.SaveRefreshToken(token); err != nil {
					t.Fatal(err)
				}
			}
			client := "client"
			if reason == "client_mismatch" {
				client = "other"
			}
			form := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {raw}}
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Request-ID", "untrusted-id")
			req.Header.Set("X-Forwarded-For", "untrusted-address")
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			want := http.StatusBadRequest
			if reason == "rotated" {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(output.String(), raw) || strings.Contains(output.String(), HashSecret(raw)) || strings.Contains(output.String(), "untrusted-") {
				t.Fatal("audit leaked sensitive or untrusted attribution")
			}
			event := "refresh_rejected"
			if reason == "rotated" {
				event = "refresh_rotated"
			}
			found, revoke := false, false
			decoder := json.NewDecoder(&output)
			for decoder.More() {
				var line struct {
					Data map[string]any `json:"data"`
				}
				if err := decoder.Decode(&line); err != nil {
					t.Fatal(err)
				}
				d := line.Data
				if d["event"] == event {
					found = true
					if d["reason"] != reason || d["client_id"] != client || d["request_id"] != rec.Header().Get("X-Request-ID") {
						t.Fatalf("uncorrelated outcome: %v", d)
					}
					if reason != "unknown" && d["family_id"] != "opaque-family" {
						t.Fatalf("missing family: %v", d)
					}
				}
				if d["event"] == "refresh_family_revoked" {
					revoke = true
					if d["family_id"] != "opaque-family" || d["outcome"] != "success" {
						t.Fatalf("bad revocation: %v", d)
					}
				}
			}
			if !found || revoke != (reason == "replay") {
				t.Fatalf("missing outcome/revocation: %v %v", found, revoke)
			}
		})
	}
}
