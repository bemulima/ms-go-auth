//go:build integration

package usecase_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/example/auth-service/internal/domain"
	oauthprovider "github.com/example/auth-service/internal/infrastructure/oauth"
	"github.com/example/auth-service/internal/usecase"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type smokeProfile struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	Email    string `json:"email"`
	Trusted  bool   `json:"trusted"`
}
type smokeBoundary struct {
	mu       sync.Mutex
	profile  smokeProfile
	key      *rsa.PrivateKey
	codes    map[string]map[string]string
	frontend string
	requests map[string]int
}

func mustSmokeURL(v string) *url.URL {
	u, e := url.Parse(v)
	if e != nil {
		panic(e)
	}
	return u
}
func (b *smokeBoundary) provider(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}
	provider, action := parts[1], parts[2]
	if b.requests == nil {
		b.requests = map[string]int{}
	}
	b.requests[provider+"/"+action]++
	if action == "authorize" {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
			http.Error(w, "protocol invalid", 400)
			return
		}
		code, _ := usecase.GenerateJTI()
		b.codes[code] = map[string]string{"challenge": q.Get("code_challenge"), "nonce": q.Get("nonce"), "provider": provider, "email": b.profile.Email, "subject": b.profile.Subject}
		target := mustSmokeURL(b.frontend + "/api/oauth/" + provider + "/callback")
		v := target.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		target.RawQuery = v.Encode()
		http.Redirect(w, r, target.String(), 302)
		return
	}
	if action == "token" {
		if r.ParseForm() != nil {
			http.Error(w, "invalid", 400)
			return
		}
		code := r.Form.Get("code")
		transaction := b.codes[code]
		if transaction == nil || transaction["provider"] != provider {
			http.Error(w, "invalid grant", 400)
			return
		}
		h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(h[:]) != transaction["challenge"] {
			http.Error(w, "PKCE rejected", 400)
			return
		}
		delete(b.codes, code)
		payload := map[string]interface{}{"access_token": "fixture-external-provider-token", "token_type": "Bearer"}
		if provider == "google" {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://accounts.google.com", "aud": "smoke-client", "sub": transaction["subject"], "email": transaction["email"], "email_verified": true, "nonce": transaction["nonce"], "exp": time.Now().Add(5 * time.Minute).Unix()})
			token.Header["kid"] = "smoke-key"
			signed, e := token.SignedString(b.key)
			if e != nil {
				http.Error(w, "token signing failed", 500)
				return
			}
			payload["id_token"] = signed
		}
		_ = json.NewEncoder(w).Encode(payload)
		return
	}
	if r.Header.Get("Authorization") == "" && action != "keys" {
		http.Error(w, "provider authorization required", 401)
		return
	}
	switch action {
	case "keys":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{"kid": "smoke-key", "alg": "RS256", "kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(b.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(b.key.E)).Bytes())}}})
	case "userinfo":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"sub": b.profile.Subject, "email": b.profile.Email, "email_verified": b.profile.Trusted})
	case "user":
		id := 0
		_, _ = fmt.Sscanf(b.profile.Subject, "%d", &id)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "login": "smoke-student"})
	case "emails":
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"email": b.profile.Email, "primary": true, "verified": b.profile.Trusted}})
	default:
		http.NotFound(w, r)
	}
}

// TestAuthSmokeServe retains the existing external-only entrypoint used by Auth E2E.
// It starts no Auth, database, NATS or SMTP runtime.
func TestAuthSmokeServe(t *testing.T) {
	if os.Getenv("AUTH_SMOKE_SERVE_EXTERNAL_ONLY") != "true" {
		t.Skip("external-only fixture opt-in required")
	}
	serveExistingExternalBoundary(t)
}

func serveExistingExternalBoundary(t *testing.T) {
	token := os.Getenv("T16_PROVIDER_TOKEN")
	if len(token) < 32 {
		t.Fatal("private fixture token required")
	}
	ready, stop := os.Getenv("T17_AUTH_READY_FILE"), os.Getenv("T17_AUTH_STOP_FILE")
	t17AuthArtifactPaths(t, ready, stop)
	frontend := mustSmokeURL(os.Getenv("AUTH_SMOKE_FRONTEND_URL"))
	if frontend.Scheme != "http" || frontend.Hostname() != "localhost" || frontend.Port() == "" {
		t.Fatal("loopback frontend required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:"+os.Getenv("AUTH_SMOKE_BOUNDARY_PORT"))
	if err != nil {
		t.Fatal("boundary listen")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		listener.Close()
		t.Fatal("fixture signing key")
	}
	b := &smokeBoundary{key: key, codes: map[string]map[string]string{}, frontend: frontend.String()}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/provider/google/") || strings.HasPrefix(r.URL.Path, "/provider/github/") {
			b.provider(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "fixture denied", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		b.mu.Lock()
		defer b.mu.Unlock()
		switch r.URL.Path {
		case "/fixture/provider":
			if r.Method != http.MethodPost {
				w.WriteHeader(405)
				return
			}
			var p smokeProfile
			if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&p) != nil {
				http.Error(w, "invalid profile", 400)
				return
			}
			valid := p.Provider == "google" && p.Subject != "" && strings.HasSuffix(p.Email, "@gmail.com")
			if p.Provider == "github" {
				id, err := strconv.ParseInt(p.Subject, 10, 64)
				valid = err == nil && id > 0 && strings.HasSuffix(p.Email, "@example.test")
			}
			if !valid {
				http.Error(w, "synthetic provider profile required", 400)
				return
			}
			b.profile = p
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "/fixture/state":
			if r.Method != http.MethodGet {
				w.WriteHeader(405)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requests": b.requests, "unconsumed_codes": len(b.codes)})
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	data, _ := json.Marshal(map[string]string{"url": "http://" + listener.Addr().String(), "classification": "external-oauth-boundary-only"})
	if os.WriteFile(ready, data, 0600) != nil {
		t.Fatal("boundary readiness")
	}
	deadline := time.Now().Add(30 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(stop); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("boundary stop required")
}

// Exercise the extracted external boundary with the actual production adapters.
// This is provider-protocol integration, not an Auth/browser E2E result.
func TestExternalOAuthBoundary(t *testing.T) {
	for _, name := range []string{"google", "github"} {
		t.Run(name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal("fixture signing key")
			}
			email, subject := "boundary@example.test", "123456"
			if name == "google" {
				email, subject = "boundary@gmail.com", "boundary-google-subject"
			}
			b := &smokeBoundary{profile: smokeProfile{Provider: name, Subject: subject, Email: email, Trusted: true}, key: key, codes: map[string]map[string]string{}, frontend: "http://localhost:3001"}
			server := httptest.NewServer(http.HandlerFunc(b.provider))
			defer server.Close()
			var provider domain.OAuthProvider
			if name == "google" {
				p := oauthprovider.NewGoogleOAuth2("smoke-client", "smoke-secret", b.frontend+"/api/oauth/google/callback")
				if p.UseLocalBoundary(server.URL) != nil {
					t.Fatal("boundary routing")
				}
				p.HTTPClient = server.Client()
				provider = p
			} else {
				p := oauthprovider.NewGitHubOAuth2("smoke-client", "smoke-secret", b.frontend+"/api/oauth/github/callback")
				if p.UseLocalBoundary(server.URL) != nil {
					t.Fatal("boundary routing")
				}
				p.HTTPClient = server.Client()
				provider = p
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.AuthorizationURL("boundary-state", "boundary-verifier"), nil)
			if err != nil {
				t.Fatal("authorization request")
			}
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			response, err := client.Do(req)
			if err != nil {
				t.Fatal("external authorization")
			}
			defer response.Body.Close()
			callback, err := url.Parse(response.Header.Get("Location"))
			if err != nil || response.StatusCode != 302 || callback.Query().Get("state") != "boundary-state" {
				t.Fatal("state-preserving callback")
			}
			code := callback.Query().Get("code")
			if code == "" {
				t.Fatal("external authorization code absent")
			}
			if _, err = provider.Authenticate(ctx, code, "incorrect-verifier"); err == nil {
				t.Fatal("PKCE mismatch accepted")
			}
			profile, err := provider.Authenticate(ctx, code, "boundary-verifier")
			if err != nil {
				t.Fatal("real production adapter rejected boundary exchange")
			}
			if profile.ProviderUserID != subject || profile.Email != email || !profile.EmailVerified {
				t.Fatal("verified external profile mismatch")
			}
			if _, err = provider.Authenticate(ctx, code, "boundary-verifier"); err == nil {
				t.Fatal("external code replay accepted")
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if len(b.codes) != 0 {
				t.Fatal("consumed external code retained")
			}
			actions := []string{"authorize", "token", "user", "emails"}
			if name == "google" {
				actions = []string{"authorize", "token", "keys", "userinfo"}
			}
			for _, action := range actions {
				if b.requests[name+"/"+action] == 0 {
					t.Fatal("production adapter bypassed external endpoint")
				}
			}
		})
	}
}
