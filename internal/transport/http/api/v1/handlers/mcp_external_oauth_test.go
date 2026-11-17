package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

type fakeMCPIssue struct{ calls int }

func (f *fakeMCPIssue) Authorize(_ context.Context, req usecase.MCPExternalAuthorizationRequest, student, state string, _ time.Time) (string, error) {
	f.calls++
	if student != "00000000-0000-4000-8000-000000000123" || req.ClientID != "ide-client" || state != strings.Repeat("s", 32) {
		return "", usecase.ErrMCPExternalDenied
	}
	return "https://client.test/cb?code=secret&state=" + state, nil
}

type fakeMCPExchange struct{ calls int }

func (f *fakeMCPExchange) Prepare(_ context.Context, req usecase.MCPExternalTokenRequest, now time.Time) (*usecase.MCPExternalAccessTokenIntent, error) {
	f.calls++
	if req.GrantType != "authorization_code" || req.Verifier != strings.Repeat("v", 43) || req.ResourceURI != "https://api.test/mcp" {
		return nil, usecase.ErrMCPExternalDenied
	}
	return &usecase.MCPExternalAccessTokenIntent{Scope: "courses:read", ExpiresAt: now.Unix() + 300}, nil
}

type fakeMCPSigner struct{}

func (fakeMCPSigner) Sign(_ *usecase.MCPExternalAccessTokenIntent) (string, error) {
	return "short-lived-signed-token", nil
}

type fakeMCPRevoker struct{ calls int }

func (f *fakeMCPRevoker) RevokeMCPExternalConsent(_ context.Context, student, client, resource string) error {
	f.calls++
	if student != "00000000-0000-4000-8000-000000000123" || client != "ide-client" || resource != "https://api.test/mcp" {
		return usecase.ErrMCPExternalDenied
	}
	return nil
}

func mcpTestHTTP(t *testing.T, method, target, body, contentType, bearer string, callback echo.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		r.Header.Set("Authorization", bearer)
	}
	w := httptest.NewRecorder()
	c := e.NewContext(r, w)
	c.Set("user_id", "00000000-0000-4000-8000-000000000123")
	if err := callback(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return w
}

func TestMCPExternalAuthorizationCompletionRequiresStudentBearerAndExactJSON(t *testing.T) {
	issue := &fakeMCPIssue{}
	h := MCPExternalOAuthHandler{Codes: issue}
	fields := map[string]string{
		"response_type": "code", "client_id": "ide-client", "redirect_uri": "https://client.test/cb",
		"resource": "https://api.test/mcp", "code_challenge": strings.Repeat("x", 43),
		"code_challenge_method": "S256", "scope": "courses:read", "state": strings.Repeat("s", 32),
	}
	encoded, _ := json.Marshal(fields)
	valid := mcpTestHTTP(t, "POST", "/", string(encoded), "application/json", "Bearer verified-frontend-token", h.CompleteAuthorization)
	if valid.Code != 200 || !strings.Contains(valid.Body.String(), "redirect_to") || issue.calls != 1 || valid.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authorized completion refused: status=%d body=%s", valid.Code, valid.Body.String())
	}
	for _, tc := range []struct{ name, payload, typ, auth string }{
		{"no-auth", string(encoded), "application/json", ""},
		{"duplicate-client", `{"response_type":"code","client_id":"x","client_id":"ide-client"}`, "application/json", "Bearer x"},
		{"unknown-field", string(encoded[:len(encoded)-1]) + `,"student_id":"forged"}`, "application/json", "Bearer x"},
		{"wrong-content-type", string(encoded), "text/plain", "Bearer x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mcpTestHTTP(t, "POST", "/", tc.payload, tc.typ, tc.auth, h.CompleteAuthorization)
			if got.Code != 400 {
				t.Fatalf("unsafe completion accepted: status=%d", got.Code)
			}
		})
	}
	if issue.calls != 1 {
		t.Fatal("invalid request reached code issuer")
	}
}

func TestMCPExternalTokenExchangeRejectsDuplicateFormsAndFrontendBearer(t *testing.T) {
	exchange := &fakeMCPExchange{}
	h := MCPExternalOAuthHandler{Tokens: exchange, Signer: fakeMCPSigner{}}
	values := url.Values{
		"grant_type": {"authorization_code"}, "code": {strings.Repeat("c", 43)},
		"code_verifier": {strings.Repeat("v", 43)}, "client_id": {"ide-client"},
		"redirect_uri": {"https://client.test/cb"}, "resource": {"https://api.test/mcp"},
	}
	valid := mcpTestHTTP(t, "POST", "/", values.Encode(), "application/x-www-form-urlencoded", "", h.ExchangeToken)
	if valid.Code != http.StatusOK || !strings.Contains(valid.Body.String(), `"access_token":"short-lived-signed-token"`) || exchange.calls != 1 {
		t.Fatalf("valid PKCE exchange refused: status=%d body=%s", valid.Code, valid.Body.String())
	}
	for _, tc := range []struct{ name, payload, auth string }{
		{"duplicate-code", values.Encode() + "&code=other", ""},
		{"extraneous-scope", values.Encode() + "&scope=admin", ""},
		{"frontend-bearer", values.Encode(), "Bearer frontend"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mcpTestHTTP(t, "POST", "/", tc.payload, "application/x-www-form-urlencoded", tc.auth, h.ExchangeToken)
			if got.Code != 400 {
				t.Fatalf("unsafe token exchange accepted: status=%d", got.Code)
			}
		})
	}
	if exchange.calls != 1 {
		t.Fatal("invalid token exchange reached code consumer")
	}
	charset := mcpTestHTTP(t, "POST", "/", values.Encode(), "application/x-www-form-urlencoded; charset=UTF-8", "", h.ExchangeToken)
	if charset.Code != 200 || exchange.calls != 2 {
		t.Fatalf("standard UTF-8 OAuth form rejected: status=%d", charset.Code)
	}
}

func TestMCPExternalStudentConsentRevokeUsesSessionIdentity(t *testing.T) {
	revoker := &fakeMCPRevoker{}
	h := MCPExternalOAuthHandler{Revoker: revoker, Resource: "https://api.test/mcp"}
	valid := `{"client_id":"ide-client","resource":"https://api.test/mcp"}`
	w := mcpTestHTTP(t, "POST", "/", valid, "application/json", "Bearer session-token", h.RevokeConsent)
	if w.Code != http.StatusNoContent || revoker.calls != 1 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("student disconnect refused: status=%d", w.Code)
	}
	for _, tc := range []struct{ name, payload, bearer string }{
		{"missing-session", valid, ""},
		{"forged-student", `{"client_id":"ide-client","resource":"https://api.test/mcp","student_id":"forged"}`, "Bearer session"},
		{"wrong-resource", `{"client_id":"ide-client","resource":"https://other.test/mcp"}`, "Bearer session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mcpTestHTTP(t, "POST", "/", tc.payload, "application/json", tc.bearer, h.RevokeConsent)
			if got.Code != 400 {
				t.Fatalf("unsafe disconnect accepted: status=%d", got.Code)
			}
		})
	}
	if revoker.calls != 1 {
		t.Fatal("unauthorized Student reached consent repository")
	}
}
