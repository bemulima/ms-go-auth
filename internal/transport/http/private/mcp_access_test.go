package internalhttp

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

type mockMCPAccessVerifier func(context.Context, string, string, time.Time) (*usecase.MCPExternalVerifiedGrant, error)

func (f mockMCPAccessVerifier) Verify(ctx context.Context, bearer, resource string, at time.Time) (*usecase.MCPExternalVerifiedGrant, error) {
	return f(ctx, bearer, resource, at)
}

func TestMCPPrivateAccessVerifierRequiresIndependentCapability(t *testing.T) {
	const resource = "https://api.example.test/mcp"
	key := strings.Repeat("K", 48)
	calls := 0
	e := echo.New()
	if err := RegisterMCPAccess(e.Group("/internal"), mockMCPAccessVerifier(func(_ context.Context, bearer, gotResource string, _ time.Time) (*usecase.MCPExternalVerifiedGrant, error) {
		calls++
		if bearer != "opaque-external-token" || gotResource != resource {
			t.Fatal("wrong trusted issuer inputs")
		}
		return &usecase.MCPExternalVerifiedGrant{
			StudentID: "student-1", ClientID: "client-1", GrantID: "consent-1",
			Audience: resource, Scopes: []string{"courses:read"}, ExpiresAt: time.Now().Add(time.Minute).Unix(),
		}, nil
	}), key, resource); err != nil {
		t.Fatal(err)
	}
	body := `{"token":"opaque-external-token","resource":"` + resource + `"}`
	for _, tc := range []struct {
		name, capability, body string
		status                 int
	}{
		{"valid", key, body, 200},
		{"missing-service-capability", "", body, 401},
		{"frontend-bearer-not-capability", "frontend-jwt", body, 401},
		{"unknown-field", key, body[:len(body)-1] + `,"actor":"forged"}`, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/internal/mcp/verify", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			if tc.capability != "" {
				req.Header.Set("X-MCP-Service-Token", tc.capability)
			}
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)
			if res.Code != tc.status || res.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
			}
		})
	}
	if calls != 1 {
		t.Fatalf("untrusted caller reached issuer readback %d times", calls)
	}
}
