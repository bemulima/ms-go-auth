package handlers

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMCPExternalBrowserStartOnlyForExactPKCEStudentRequest(t *testing.T) {
	h := MCPExternalOAuthHandler{
		Resource:     "https://api.test/mcp",
		ConsentUIURI: "https://web.test/student/mcp/consent",
	}
	params := url.Values{
		"response_type": {"code"}, "client_id": {"registered-cli"},
		"redirect_uri": {"http://127.0.0.1:8080/callback"}, "resource": {"https://api.test/mcp"},
		"code_challenge": {strings.Repeat("x", 43)}, "code_challenge_method": {"S256"},
		"scope": {"courses:read"}, "state": {strings.Repeat("s", 32)},
	}
	for _, scope := range []string{"courses:read", "profile:read", "tasks:read"} {
		t.Run("allow-"+scope, func(t *testing.T) {
			q := url.Values{}
			for key, values := range params {
				q[key] = append([]string(nil), values...)
			}
			q.Set("scope", scope)
			w := mcpTestHTTP(t, http.MethodGet, "/authorize?"+q.Encode(), "", "", "", h.StartBrowserAuthorization)
			if w.Code != http.StatusFound || w.Header().Get("Cache-Control") != "no-store" ||
				w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("browser start scope=%q status=%d", scope, w.Code)
			}
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil || location.Scheme != "https" || location.Host != "web.test" ||
				location.Path != "/student/mcp/consent" ||
				location.Query().Get("state") != q.Get("state") ||
				location.Query().Get("scope") != scope ||
				location.Query().Get("redirect_uri") != q.Get("redirect_uri") {
				t.Fatalf("browser start unsafe location for scope=%q: %v %v", scope, location, err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func(url.Values)
	}{
		{"duplicate-client", func(q url.Values) { q.Add("client_id", "attacker") }},
		{"additional-student", func(q url.Values) { q.Set("student_id", "forged") }},
		{"wrong-resource", func(q url.Values) { q.Set("resource", "https://other.test/mcp") }},
		{"admin-scope", func(q url.Values) { q.Set("scope", "admin:write") }},
		{"unapproved-calendar-scope", func(q url.Values) { q.Set("scope", "calendar:read") }},
		{"unapproved-teacher-scope", func(q url.Values) { q.Set("scope", "teacher:ask") }},
		{"unapproved-practice-write-scope", func(q url.Values) { q.Set("scope", "tasks:write") }},
		{"combined-read-scopes", func(q url.Values) { q.Set("scope", "courses:read tasks:read") }},
		{"unknown-read-scope", func(q url.Values) { q.Set("scope", "assessments:read") }},
		{"pkce-plain", func(q url.Values) { q.Set("code_challenge_method", "plain") }},
		{"short-state", func(q url.Values) { q.Set("state", "short") }},
		{"foreign-http-callback", func(q url.Values) { q.Set("redirect_uri", "http://evil.test/cb") }},
		{"callback-injection", func(q url.Values) { q.Set("redirect_uri", "https://evil.test/cb?code=stolen") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			for key, values := range params {
				q[key] = append([]string(nil), values...)
			}
			tc.edit(q)
			got := mcpTestHTTP(t, http.MethodGet, "/authorize?"+q.Encode(), "", "", "", h.StartBrowserAuthorization)
			if got.Code != http.StatusBadRequest || got.Header().Get("Location") != "" {
				t.Fatalf("unsafe browser start admitted status=%d", got.Code)
			}
		})
	}
}

func TestMCPExternalBrowserUIIsFixedHTTPSDestination(t *testing.T) {
	for _, raw := range []string{
		"", "http://web.test/student/mcp/consent", "https://evil@web.test/student/mcp/consent",
		"https://web.test/other", "https://web.test/student/mcp/consent?redirect=https://evil.test",
	} {
		h := MCPExternalOAuthHandler{Resource: "https://api.test/mcp", ConsentUIURI: raw}
		if h.ValidateBrowserUI() == nil {
			t.Fatalf("unsafe browser URL accepted: %q", raw)
		}
	}
}
