package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestGoogleOAuth2NormalizesProfileFields(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	id := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "google-1", "email": "user@example.com", "email_verified": true, "hd": "example.com", "iss": "https://accounts.google.com", "aud": "client", "exp": time.Now().Add(time.Minute).Unix(), "nonce": googleNonce("verifier")})
	id.Header["kid"] = "test"
	signed, err := id.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":"token","token_type":"Bearer","id_token":%q}`, signed)
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{"kid": "test", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"sub":"google-1","email":"user@example.com","email_verified":true,"name":"Ada Lovelace","given_name":" Ada ","family_name":" Lovelace ","birthdate":"1998-12-10","gender":"FEMALE","picture":"https://lh3.googleusercontent.com/a/avatar"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGoogleOAuth2("client", "secret", "http://localhost/callback")
	provider.Config.Endpoint = oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
	provider.HTTPClient = server.Client()
	provider.userInfoURL = server.URL + "/userinfo"
	provider.JWKSURL = server.URL + "/keys"

	profile, err := provider.Authenticate(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if profile.FirstName != "Ada" || profile.LastName != "Lovelace" || profile.BirthYear == nil || *profile.BirthYear != 1998 || profile.Gender != "female" || profile.AvatarURL != "https://lh3.googleusercontent.com/a/avatar" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
}

func TestGitHubOAuth2KeepsCombinedNameOutOfStructuredFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = fmt.Fprint(w, `{"access_token":"token","token_type":"bearer"}`)
		case "/user":
			_, _ = fmt.Fprint(w, `{"id":1,"login":"ada","name":"Ada Lovelace","avatar_url":"https://avatars.githubusercontent.com/u/1?v=4"}`)
		case "/emails":
			_, _ = fmt.Fprint(w, `[{"email":"user@example.com","primary":true,"verified":true}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGitHubOAuth2("client", "secret", "http://localhost/callback")
	provider.Config.Endpoint = oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
	provider.HTTPClient = server.Client()
	provider.userURL = server.URL + "/user"
	provider.emailsURL = server.URL + "/emails"

	profile, err := provider.Authenticate(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if profile.DisplayName != "Ada Lovelace" || profile.FirstName != "" || profile.LastName != "" || profile.AvatarURL != "https://avatars.githubusercontent.com/u/1?v=4" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
}

func TestGoogleLocalBoundaryOnlyChangesExternalEndpoints(t *testing.T) {
	p := NewGoogleOAuth2("client", "secret", "http://localhost/callback")
	for _, raw := range []string{"https://example.com", "http://example.com:80", "http://127.0.0.1", "http://user@localhost:1234", "http://localhost:1234/path", "http://localhost:1234?secret=value"} {
		if p.UseLocalBoundary(raw) == nil {
			t.Fatal("unsafe boundary accepted")
		}
	}
	if p.UseLocalBoundary("http://127.0.0.1:1234") != nil {
		t.Fatal("local origin rejected")
	}
	if p.Config.Endpoint.TokenURL != "http://127.0.0.1:1234/provider/google/token" || p.JWKSURL != "http://127.0.0.1:1234/provider/google/keys" || p.userInfoURL != "http://127.0.0.1:1234/provider/google/userinfo" {
		t.Fatal("external endpoint routing mismatch")
	}
	if p.Config.ClientID != "client" || p.Config.RedirectURL != "http://localhost/callback" {
		t.Fatal("OAuth client contract changed")
	}
}

func TestGitHubLocalBoundaryOnlyChangesExternalEndpoints(t *testing.T) {
	p := NewGitHubOAuth2("client", "secret", "http://localhost/callback")
	for _, raw := range []string{"https://example.com", "http://example.com:80", "http://127.0.0.1", "http://user@localhost:1234", "http://localhost:1234/path", "http://localhost:1234?secret=value"} {
		if p.UseLocalBoundary(raw) == nil {
			t.Fatal("unsafe GitHub boundary accepted")
		}
	}
	if p.UseLocalBoundary("http://127.0.0.1:1234") != nil {
		t.Fatal("local origin rejected")
	}
	if p.Config.Endpoint.TokenURL != "http://127.0.0.1:1234/provider/github/token" || p.userURL != "http://127.0.0.1:1234/provider/github/user" || p.emailsURL != "http://127.0.0.1:1234/provider/github/emails" {
		t.Fatal("external GitHub endpoints mismatch")
	}
	if p.Config.ClientID != "client" || p.Config.RedirectURL != "http://localhost/callback" {
		t.Fatal("OAuth client contract changed")
	}
}
