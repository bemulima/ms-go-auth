package internalhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

type mentorPrivateVerifier struct {
	calls  int
	denied bool
}

func (v *mentorPrivateVerifier) Verify(context.Context, string, string, time.Time) (*usecase.MCPMentorVerifiedGrant, error) {
	v.calls++
	if v.denied {
		return nil, domain.ErrMCPMentorDenied
	}
	return &usecase.MCPMentorVerifiedGrant{Persona: "MENTOR", MentorID: "10000000-0000-4000-8000-000000000001", ClientID: "mentor-client", GrantID: "20000000-0000-4000-8000-000000000001", Audience: "https://api.example.test/mcp", Scopes: []string{"mentor:profile:read"}, ExpiresAt: 1800000000, OwnerProof: "internal-proof"}, nil
}
func personaSelectorJWT(typ string) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": typ})
	return base64.RawURLEncoding.EncodeToString(header) + ".e30.c2ln"
}
func TestMCPMentorPrivateDispatcherIsTerminalAndStudentWireUnchanged(t *testing.T) {
	e := echo.New()
	mentor := &mentorPrivateVerifier{}
	studentCalls := 0
	student := mockMCPAccessVerifier(func(context.Context, string, string, time.Time) (*usecase.MCPExternalVerifiedGrant, error) {
		studentCalls++
		return &usecase.MCPExternalVerifiedGrant{StudentID: "student", ClientID: "student-client", GrantID: "student-grant", Audience: "https://api.example.test/mcp", Scopes: []string{"profile:read"}, ExpiresAt: 1800000000}, nil
	})
	capability := strings.Repeat("K", 48)
	resource := "https://api.example.test/mcp"
	if err := RegisterMCPPersonaAccess(e.Group("/internal"), student, mentor, capability, resource); err != nil {
		t.Fatal(err)
	}
	call := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"token": token, "resource": resource})
		r := httptest.NewRequest("POST", "/internal/mcp/verify", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-MCP-Service-Token", capability)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	w := call(personaSelectorJWT("mentor-at+jwt"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"persona":"MENTOR"`) || strings.Contains(w.Body.String(), "student_id") {
		t.Fatal("Mentor wire mismatch")
	}
	w = call(personaSelectorJWT("at+jwt"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"student_id":"student"`) || strings.Contains(w.Body.String(), "persona") || strings.Contains(w.Body.String(), "owner_proof") {
		t.Fatal("legacy Student wire changed")
	}
	mentor.denied = true
	w = call(personaSelectorJWT("mentor-at+jwt"))
	if w.Code != 401 || studentCalls != 1 || mentor.calls != 2 {
		t.Fatal("failed Mentor verifier fell back to Student")
	}
	w = call(personaSelectorJWT("JWT"))
	if w.Code != 401 || studentCalls != 1 || mentor.calls != 2 {
		t.Fatal("frontend JWT reached a verifier")
	}
}
func TestMCPMentorPrivateExactRequestAndIndependentCapability(t *testing.T) {
	e := echo.New()
	mentor := &mentorPrivateVerifier{}
	capability := strings.Repeat("K", 48)
	resource := "https://api.example.test/mcp"
	if err := RegisterMCPPersonaAccess(e.Group("/internal"), nil, mentor, capability, resource); err != nil {
		t.Fatal(err)
	}
	valid := `{"token":"` + personaSelectorJWT("mentor-at+jwt") + `","resource":"` + resource + `"}`
	for _, test := range []struct{ name, body, cap, header, value string }{
		{"no capability", valid, "", "", ""},
		{"duplicate token", strings.TrimSuffix(valid, "}") + `,"token":"x"}`, capability, "", ""},
		{"caller identity", strings.TrimSuffix(valid, "}") + `,"mentor_id":"forged"}`, capability, "", ""},
		{"aliased key", strings.Replace(valid, `"token"`, `"t\u006fken"`, 1), capability, "", ""},
		{"external bearer", valid, capability, "Authorization", "Bearer frontend"},
		{"cookie", valid, capability, "Cookie", "session=frontend"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/internal/mcp/verify", strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-MCP-Service-Token", test.cap)
			if test.header != "" {
				r.Header.Set(test.header, test.value)
			}
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if w.Code != 401 || mentor.calls != 0 {
				t.Fatal("untrusted request reached authority")
			}
		})
	}
}
