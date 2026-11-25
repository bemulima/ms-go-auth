package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

type mentorHTTPSession struct {
	calls     int
	failAfter int
}

func (s *mentorHTTPSession) VerifyToken(_ context.Context, _ string, bearer string) (*usecase.VerificationResult, error) {
	s.calls++
	if bearer != "live-web-session" || (s.failAfter > 0 && s.calls > s.failAfter) {
		return nil, usecase.ErrMentorSessionUnauthenticated
	}
	return &usecase.VerificationResult{UserID: "10000000-0000-4000-8000-000000000001"}, nil
}

type mentorHTTPOAuth struct {
	previews, approvals, revokes, exchanges int
	subject                                 string
}

func (s *mentorHTTPOAuth) Preview(_ context.Context, r usecase.MCPMentorAuthorizationRequest, subject string) (*usecase.MCPMentorConsentPreview, error) {
	s.previews++
	s.subject = subject
	return &usecase.MCPMentorConsentPreview{Persona: "MENTOR", ClientID: r.ClientID, ClientName: "Registered client", Resource: r.Resource, Scopes: []string{domain.MCPMentorScope}}, nil
}
func (s *mentorHTTPOAuth) Approve(_ context.Context, r usecase.MCPMentorAuthorizationRequest, subject string) (string, error) {
	s.approvals++
	s.subject = subject
	return r.RedirectURI + "?code=" + strings.Repeat("A", 43) + "&state=" + r.State, nil
}
func (s *mentorHTTPOAuth) Revoke(_ context.Context, subject, client, resource string) error {
	s.revokes++
	s.subject = subject
	return nil
}
func (s *mentorHTTPOAuth) Exchange(context.Context, usecase.MCPExternalTokenRequest) (*usecase.MCPMentorTokenResponse, error) {
	s.exchanges++
	return &usecase.MCPMentorTokenResponse{AccessToken: "mentor-oauth-token", TokenType: "Bearer", ExpiresIn: 300, Scope: domain.MCPMentorScope}, nil
}
func mentorHTTPFields() map[string]string {
	return map[string]string{"response_type": "code", "client_id": "mentor-client", "redirect_uri": "https://client.example.test/callback", "resource": "https://api.example.test/mcp", "code_challenge": strings.Repeat("A", 43), "code_challenge_method": "S256", "scope": "mentor:profile:read", "state": strings.Repeat("S", 24)}
}
func mentorHTTPFixture() (*echo.Echo, *mentorHTTPOAuth, *mentorHTTPSession) {
	e := echo.New()
	oauth := &mentorHTTPOAuth{}
	sessions := &mentorHTTPSession{}
	h := MCPMentorHandler{OAuth: oauth, Sessions: sessions, Resource: "https://api.example.test/mcp", ConsentUI: "https://mentor.example.test/mentor/mcp/consent"}
	e.GET("/authorize", h.Authorize)
	e.GET("/consent", h.Consent)
	e.POST("/consent", h.Consent)
	e.POST("/revoke", h.Revoke)
	e.POST("/token", h.Token)
	return e, oauth, sessions
}
func mentorHTTPCall(e *echo.Echo, method, path, body, contentType string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if auth {
		r.Header.Set("Authorization", "Bearer live-web-session")
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}
func TestMCPMentorHTTPFirstPartyRedirectPreviewAndExplicitApproval(t *testing.T) {
	e, oauth, sessions := mentorHTTPFixture()
	fields := mentorHTTPFields()
	query := url.Values{}
	for k, v := range fields {
		query.Set(k, v)
	}
	w := mentorHTTPCall(e, "GET", "/authorize?"+query.Encode(), "", "", false)
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "https://mentor.example.test/mentor/mcp/consent?") || oauth.approvals != 0 || sessions.calls != 0 {
		t.Fatal("browser GET performed authorization")
	}
	w = mentorHTTPCall(e, "GET", "/consent?"+query.Encode(), "", "", true)
	if w.Code != 200 || oauth.previews != 1 || oauth.approvals != 0 || sessions.calls != 2 {
		t.Fatal("preview wrote grant or skipped session recheck")
	}
	body, _ := json.Marshal(fields)
	w = mentorHTTPCall(e, "POST", "/consent", string(body), "application/json", true)
	if w.Code != 200 || oauth.approvals != 1 || oauth.subject != "10000000-0000-4000-8000-000000000001" || !strings.Contains(w.Body.String(), "redirect_uri") {
		t.Fatal("explicit consent did not use verified subject")
	}
	w = mentorHTTPCall(e, "POST", "/revoke", `{"client_id":"mentor-client","resource":"https://api.example.test/mcp"}`, "application/json", true)
	if w.Code != 204 || oauth.revokes != 1 {
		t.Fatal("disconnect failed")
	}
}
func TestMCPMentorHTTPRejectsCallerIdentityCookieJSONAliasesAndLostSession(t *testing.T) {
	fields := mentorHTTPFields()
	body, _ := json.Marshal(fields)
	for _, test := range []struct {
		name, body   string
		cookie, auth bool
	}{
		{"missing session", string(body), false, false},
		{"caller subject", strings.TrimSuffix(string(body), "}") + `,"mentor_id":"forged"}`, false, true},
		{"duplicated field", strings.TrimSuffix(string(body), "}") + `,"scope":"mentor:profile:read"}`, false, true},
		{"aliased key", strings.Replace(string(body), `"scope"`, `"sc\u006fpe"`, 1), false, true},
		{"cookie authority", string(body), true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, oauth, _ := mentorHTTPFixture()
			r := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			if test.auth {
				r.Header.Set("Authorization", "Bearer live-web-session")
			}
			if test.cookie {
				r.Header.Set("Cookie", "session=secret")
			}
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if (w.Code != 400 && w.Code != 401) || oauth.approvals != 0 {
				t.Fatal("forged authority reached consent writer")
			}
		})
	}
	e, oauth, sessions := mentorHTTPFixture()
	sessions.failAfter = 1
	w := mentorHTTPCall(e, "POST", "/consent", string(body), "application/json", true)
	if w.Code != 401 || oauth.approvals != 1 || strings.Contains(w.Body.String(), "code") {
		t.Fatal("session revoked during approval still received code")
	}
}
