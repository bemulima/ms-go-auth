package internalhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const (
	mentorHTTPActor   = "11111111-1111-4111-8111-111111111111"
	mentorHTTPTarget  = "22222222-2222-4222-8222-222222222222"
	mentorHTTPApp     = "33333333-3333-4333-8333-333333333333"
	mentorHTTPRequest = "44444444-4444-4444-8444-444444444444"
	mentorHTTPSID     = "55555555-5555-4555-8555-555555555555"
)

var mentorHTTPKeys struct {
	sync.Once
	keys [2]*rsa.PrivateKey
	err  error
}

func mentorHTTPKeyPair(t *testing.T, index int) (string, string) {
	t.Helper()
	mentorHTTPKeys.Do(func() {
		for i := range mentorHTTPKeys.keys {
			mentorHTTPKeys.keys[i], mentorHTTPKeys.err = rsa.GenerateKey(rand.Reader, 2048)
			if mentorHTTPKeys.err != nil {
				return
			}
		}
	})
	if mentorHTTPKeys.err != nil {
		t.Fatal("ephemeral test keys unavailable")
	}
	key := mentorHTTPKeys.keys[index]
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
}

type mentorHTTPStore struct {
	calls     int
	err       error
	revoked   bool
	nilResult bool
	deadline  time.Duration
	after     func()
}

func (s *mentorHTTPStore) FindActive(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	s.calls++
	if d, ok := ctx.Deadline(); ok {
		s.deadline = time.Until(d)
	}
	if s.after != nil {
		s.after()
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.nilResult {
		return nil, nil
	}
	if s.revoked {
		return nil, domain.ErrNotFound
	}
	if hash != "rt:"+mentorHTTPSID {
		return nil, domain.ErrNotFound
	}
	return &domain.RefreshToken{UserID: mentorHTTPActor, RefreshTokenHash: hash, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type mentorHTTPOwners struct {
	calls, intents int
	allow          bool
	err            error
	after          func()
	seen           domain.MentorRoleDecisionBinding
}

func (a *mentorHTTPOwners) ConfirmCanonicalAdmin(_ context.Context, actor string) (*domain.CanonicalAdminConfirmation, error) {
	a.calls++
	if a.after != nil {
		a.after()
	}
	if a.err != nil {
		return nil, a.err
	}
	return &domain.CanonicalAdminConfirmation{ActorID: actor, UniqueCanonicalDefaultAdmin: a.allow}, nil
}
func (a *mentorHTTPOwners) ConfirmCommittedMentorIntent(_ context.Context, b domain.MentorRoleDecisionBinding) (*domain.MentorCommittedIntentConfirmation, error) {
	a.intents++
	a.seen = b
	if a.err != nil {
		return nil, a.err
	}
	state := domain.MentorApprovalPendingGrant
	if b.Decision == "SUSPEND" {
		state = domain.MentorSuspended
	}
	return &domain.MentorCommittedIntentConfirmation{Binding: b, Committed: true, Current: true, State: state}, nil
}

func mentorHTTPFixture(t *testing.T) (*MentorHTTPAuthorityHandler, *mentorHTTPStore, *mentorHTTPOwners, usecase.JWTSigner, string) {
	t.Helper()
	accessPrivate, accessPublic := mentorHTTPKeyPair(t, 0)
	proofPrivate, proofPublic := mentorHTTPKeyPair(t, 1)
	signer, err := usecase.NewJWTSigner(&config.Config{JWTPrivateKey: accessPrivate, JWTPublicKey: accessPublic, JWTIssuer: "http-source-test", JWTAudience: "http-test-client"})
	if err != nil {
		t.Fatal("actual signer unavailable")
	}
	store := &mentorHTTPStore{}
	owners := &mentorHTTPOwners{allow: true}
	sessions, err := usecase.NewMentorLiveSessionVerifier(signer, store)
	if err != nil {
		t.Fatal("actual session verifier unavailable")
	}
	authority, err := usecase.NewMentorHTTPAuthority(proofPrivate, proofPublic, sessions, owners, owners)
	if err != nil {
		t.Fatal("actual authority unavailable")
	}
	h, err := NewMentorHTTPAuthorityHandler(authority)
	if err != nil {
		t.Fatal("HTTP handler unavailable")
	}
	token, err := signer.SignAccessToken(mentorHTTPActor, map[string]any{"sid": mentorHTTPSID, "role": "admin"}, time.Minute)
	if err != nil {
		t.Fatal("actual test session token unavailable")
	}
	return h, store, owners, signer, token
}

func mentorHTTPBody(decision string, revision int64) string {
	binding := decision + "|" + mentorHTTPActor + "|" + mentorHTTPApp + "|" + mentorHTTPRequest + "|"
	switch revision {
	case 2:
		binding += "1"
	case 3:
		binding += "2"
	case 4:
		binding += "3"
	}
	digest := sha256.Sum256([]byte(binding))
	raw, _ := json.Marshal(map[string]any{"target_user_id": mentorHTTPTarget, "application_id": mentorHTTPApp, "application_revision": revision, "decision": decision, "request_id": mentorHTTPRequest, "decision_digest": hex.EncodeToString(digest[:])})
	return string(raw)
}
func mentorHTTPReq(path, body, token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://auth.example.test"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	return r
}
func mentorHTTPResult(t *testing.T, h http.Handler, r *http.Request, status int) map[string]string {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("unexpected status: got %d want %d", w.Code, status)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("response cache/JSON headers missing")
	}
	var body map[string]string
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 1 {
		t.Fatal("response is not exact one-field JSON")
	}
	return body
}

func TestMentorHTTPAuthorityExactSuccessfulOperations(t *testing.T) {
	for _, path := range []string{MentorSessionVerifyPath, MentorAdminSessionVerifyPath} {
		t.Run(path, func(t *testing.T) {
			h, s, a, _, token := mentorHTTPFixture(t)
			r := mentorHTTPReq(path, "{}", token)
			r.Header.Set("X-User-ID", mentorHTTPTarget)
			r.Header.Set("X-Actor-ID", mentorHTTPTarget)
			r.Header.Set("X-Role", "admin")
			r.Header.Set("X-Request-ID", "must-not-appear")
			body := mentorHTTPResult(t, h, r, 200)
			if body["user_id"] != mentorHTTPActor {
				t.Fatal("request header substituted for derived actor")
			}
			if s.deadline <= 0 || s.deadline > 3*time.Second {
				t.Fatal("unbounded authority operation")
			}
			want := 0
			if path == MentorAdminSessionVerifyPath {
				want = 1
			}
			if a.calls != want || a.intents != 0 {
				t.Fatal("wrong authority boundary for operation")
			}
		})
	}
	for _, tc := range []struct {
		decision string
		revision int64
	}{{"APPROVE", 2}, {"SUSPEND", 3}, {"SUSPEND", 4}} {
		t.Run(tc.decision+string(rune('0'+tc.revision)), func(t *testing.T) {
			h, s, a, _, token := mentorHTTPFixture(t)
			body := mentorHTTPResult(t, h, mentorHTTPReq(MentorRoleDecisionPath, mentorHTTPBody(tc.decision, tc.revision), token), 200)
			proof := body["proof"]
			verified, err := jwt.Parse(proof, func(*jwt.Token) (any, error) { return &mentorHTTPKeys.keys[1].PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(domain.MentorRoleDecisionIssuer), jwt.WithAudience(domain.MentorRoleDecisionAudience))
			if err != nil || verified == nil || !verified.Valid || a.calls != 1 || a.intents != 1 || s.calls != 2 || a.seen.AdminActorID != mentorHTTPActor || a.seen.Decision != tc.decision || a.seen.ApplicationRevision != tc.revision {
				t.Fatal("actual strict source issuer or exact binding not reached")
			}
		})
	}
}

func TestMentorHTTPAuthorityStrictRequestFraming(t *testing.T) {
	cases := []struct {
		name   string
		change func(*http.Request)
		want   int
		code   string
	}{
		{"unknown route", func(r *http.Request) { r.URL.Path += "/" }, 404, "not_found"},
		{"wrong case route", func(r *http.Request) { r.URL.Path = strings.ReplaceAll(r.URL.Path, "mentor", "Mentor") }, 404, "not_found"},
		{"method", func(r *http.Request) { r.Method = "GET" }, 405, "method_not_allowed"},
		{"plain HTTP", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }, 400, "invalid_request"},
		{"query", func(r *http.Request) { r.URL.RawQuery = "actor=" + mentorHTTPTarget }, 400, "invalid_request"},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, 400, "invalid_request"},
		{"fragment", func(r *http.Request) { r.URL.Fragment = "secret" }, 400, "invalid_request"},
		{"escaped route", func(r *http.Request) { r.URL.RawPath = "/internal/v1/mentor/%73ession/verify" }, 400, "invalid_request"},
		{"missing content type", func(r *http.Request) { r.Header.Del("Content-Type") }, 400, "invalid_request"},
		{"multiple content type", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400, "invalid_request"},
		{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400, "invalid_request"},
		{"unknown type parameter", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; boundary=x") }, 400, "invalid_request"},
		{"wrong charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }, 400, "invalid_request"},
		{"duplicate charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8; charset=utf-8") }, 400, "invalid_request"},
		{"extended charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset*=utf-8''utf-8") }, 400, "invalid_request"},
		{"empty charset parameter", func(r *http.Request) { r.Header.Set("Content-Type", "application/json;") }, 400, "invalid_request"},
		{"trailing charset parameter", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8;") }, 400, "invalid_request"},
		{"missing bearer", func(r *http.Request) { r.Header.Del("Authorization") }, 401, "unauthenticated"},
		{"duplicate bearer", func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }, 401, "unauthenticated"},
		{"case duplicate header", func(r *http.Request) { r.Header["authorization"] = []string{r.Header.Get("Authorization")} }, 401, "unauthenticated"},
		{"comma credentials", func(r *http.Request) { r.Header.Set("Authorization", r.Header.Get("Authorization")+",x") }, 401, "unauthenticated"},
		{"header extra whitespace", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer  "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		}, 401, "unauthenticated"},
		{"header tab", func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), " ", "\t", 1))
		}, 401, "unauthenticated"},
		{"wrong scheme", func(r *http.Request) { r.Header.Set("Authorization", "Basic synthetic") }, 401, "unauthenticated"},
		{"empty token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }, 401, "unauthenticated"},
		{"oversized token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 8193)) }, 401, "unauthenticated"},
		{"misplaced padding", func(r *http.Request) { r.Header.Set("Authorization", "Bearer a=b") }, 401, "unauthenticated"},
		{"nonascii token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer сессия") }, 401, "unauthenticated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, s, a, _, token := mentorHTTPFixture(t)
			r := mentorHTTPReq(MentorSessionVerifyPath, "{}", token)
			tc.change(r)
			body := mentorHTTPResult(t, h, r, tc.want)
			if body["error"] != tc.code || s.calls+a.calls+a.intents != 0 {
				t.Fatal("invalid framing reached authority or wrong generic code")
			}
		})
	}
	h, _, _, _, token := mentorHTTPFixture(t)
	r := mentorHTTPReq(MentorSessionVerifyPath, "{}", token)
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "Bearer", "bEaReR", 1))
	if body := mentorHTTPResult(t, h, r, 200); body["user_id"] != mentorHTTPActor {
		t.Fatal("supported MIME/scheme casing rejected")
	}
}

func TestMentorHTTPAuthorityStrictBodies(t *testing.T) {
	for name, body := range map[string]string{"empty": "", "null": "null", "array": "[]", "scalar": "true", "unknown": "{\"actor\":\"x\"}", "trailing": "{}{}", "invalid UTF8": "{\"x\":\"\xff\"}", "unpaired surrogate": "{\"x\":\"\\ud800\"}", "oversize": strings.Repeat(" ", 16385) + "{}"} {
		t.Run("session/"+name, func(t *testing.T) {
			h, s, a, _, token := mentorHTTPFixture(t)
			result := mentorHTTPResult(t, h, mentorHTTPReq(MentorSessionVerifyPath, body, token), 400)
			if result["error"] != "invalid_request" || s.calls+a.calls+a.intents != 0 {
				t.Fatal("invalid session JSON reached authority")
			}
		})
	}
	valid := mentorHTTPBody("APPROVE", 2)
	cases := map[string]string{
		"missing": "{}", "null": "null", "array": "[]", "trailing": valid + "{}", "unknown": strings.TrimSuffix(valid, "}") + ",\"actor\":\"x\"}",
		"duplicate":         strings.TrimSuffix(valid, "}") + ",\"decision\":\"APPROVE\"}",
		"escaped duplicate": strings.TrimSuffix(valid, "}") + ",\"deci\\u0073ion\":\"APPROVE\"}",
		"case alias":        strings.Replace(valid, "\"decision\"", "\"Decision\"", 1),
		"null field":        strings.Replace(valid, "\"decision\":\"APPROVE\"", "\"decision\":null", 1),
		"number string":     strings.Replace(valid, "\"application_revision\":2", "\"application_revision\":\"2\"", 1),
		"fraction":          strings.Replace(valid, "\"application_revision\":2", "\"application_revision\":2.0", 1),
		"exponent":          strings.Replace(valid, "\"application_revision\":2", "\"application_revision\":2e0", 1),
		"null revision":     strings.Replace(valid, "\"application_revision\":2", "\"application_revision\":null", 1),
		"negative revision": strings.Replace(valid, "\"application_revision\":2", "\"application_revision\":-2", 1),
		"overflow revision": strings.Replace(valid, "\"application_revision\":2", "\"application_revision\":9223372036854775808", 1),
		"uppercase UUID":    strings.Replace(valid, mentorHTTPApp, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", 1),
		"wrong revision":    strings.Replace(valid, "\"application_revision\":2", "\"application_revision\":3", 1),
		"foreign scope":     strings.TrimSuffix(valid, "}") + ",\"service\":\"default\"}",
		"body credential":   strings.TrimSuffix(valid, "}") + ",\"token\":\"synthetic\"}",
	}
	for name, body := range cases {
		t.Run("issuance/"+name, func(t *testing.T) {
			h, s, a, _, token := mentorHTTPFixture(t)
			result := mentorHTTPResult(t, h, mentorHTTPReq(MentorRoleDecisionPath, body, token), 400)
			if result["error"] != "invalid_request" || s.calls+a.calls+a.intents != 0 {
				t.Fatal("invalid issuance body reached authority")
			}
		})
	}
}

func TestMentorHTTPAuthoritySessionOwnerAndCancellationFailures(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		change     func(*mentorHTTPStore, *mentorHTTPOwners)
		status     int
		code       string
	}{
		{"revoked", MentorSessionVerifyPath, func(s *mentorHTTPStore, _ *mentorHTTPOwners) { s.revoked = true }, 401, "unauthenticated"},
		{"lookup outage", MentorSessionVerifyPath, func(s *mentorHTTPStore, _ *mentorHTTPOwners) {
			s.err = errors.New("do not disclose database diagnostic")
		}, 503, "unavailable"},
		{"nil lookup", MentorSessionVerifyPath, func(s *mentorHTTPStore, _ *mentorHTTPOwners) { s.nilResult = true }, 503, "unavailable"},
		{"not Admin", MentorAdminSessionVerifyPath, func(_ *mentorHTTPStore, a *mentorHTTPOwners) { a.allow = false }, 403, "forbidden"},
		{"owner outage", MentorAdminSessionVerifyPath, func(_ *mentorHTTPStore, a *mentorHTTPOwners) {
			a.err = errors.New("private signed owner transport detail")
		}, 503, "unavailable"},
		{"revoked during Admin read", MentorAdminSessionVerifyPath, func(s *mentorHTTPStore, a *mentorHTTPOwners) { a.after = func() { s.revoked = true } }, 401, "unauthenticated"},
		{"issuance session outage", MentorRoleDecisionPath, func(s *mentorHTTPStore, _ *mentorHTTPOwners) { s.err = domain.ErrMentorSessionUnavailable }, 503, "unavailable"},
		{"issuance revoked", MentorRoleDecisionPath, func(s *mentorHTTPStore, _ *mentorHTTPOwners) { s.revoked = true }, 401, "unauthenticated"},
		{"issuance non Admin", MentorRoleDecisionPath, func(_ *mentorHTTPStore, a *mentorHTTPOwners) { a.allow = false }, 403, "forbidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s, a, _, token := mentorHTTPFixture(t)
			tc.change(s, a)
			body := "{}"
			if tc.path == MentorRoleDecisionPath {
				body = mentorHTTPBody("APPROVE", 2)
			}
			result := mentorHTTPResult(t, h, mentorHTTPReq(tc.path, body, token), tc.status)
			if result["error"] != tc.code {
				t.Fatal("failure classification or sanitized envelope wrong")
			}
		})
	}
	h, s, _, _, token := mentorHTTPFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	s.after = cancel
	r := mentorHTTPReq(MentorSessionVerifyPath, "{}", token).WithContext(ctx)
	if result := mentorHTTPResult(t, h, r, 503); result["error"] != "unavailable" {
		t.Fatal("cancelled operation returned identity")
	}
	if h, err := NewMentorHTTPAuthorityHandler(nil); h != nil || err == nil {
		t.Fatal("missing concrete authority admitted")
	}
	if h, err := NewMentorHTTPAuthorityHandler(&usecase.MentorHTTPAuthority{}); h != nil || err == nil {
		t.Fatal("zero concrete authority admitted")
	}
	var missing *MentorHTTPAuthorityHandler
	if result := mentorHTTPResult(t, missing, mentorHTTPReq(MentorSessionVerifyPath, "{}", token), 503); result["error"] != "unavailable" {
		t.Fatal("nil handler failed open")
	}
}

func TestMentorHTTPAuthorityActualEphemeralTLSAndUnmountedDefaultRouter(t *testing.T) {
	h, _, _, _, token := mentorHTTPFixture(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	r, err := http.NewRequest(http.MethodPost, server.URL+MentorSessionVerifyPath, strings.NewReader("{}"))
	if err != nil {
		t.Fatal("request setup failed")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal("actual ephemeral TLS request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	var body map[string]string
	if err != nil || json.Unmarshal(raw, &body) != nil || response.StatusCode != 200 || body["user_id"] != mentorHTTPActor {
		t.Fatal("actual TLS HTTP boundary failed")
	}
	e := echo.New()
	Register(e.Group("/internal"))
	w := httptest.NewRecorder()
	e.ServeHTTP(w, mentorHTTPReq(MentorSessionVerifyPath, "{}", token))
	if w.Code != 404 {
		t.Fatal("new authority route unexpectedly mounted in existing router")
	}
}
