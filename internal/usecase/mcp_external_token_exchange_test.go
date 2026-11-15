package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
)

type fakeMCPExternalGrantReadback struct {
	status *domain.MCPExternalTokenGrantStatus
	err    error
	calls  atomic.Int64
}

func (f *fakeMCPExternalGrantReadback) ReadbackMCPExternalTokenGrant(
	_ context.Context, _, _, _, _ string, _ time.Time,
) (*domain.MCPExternalTokenGrantStatus, error) {
	f.calls.Add(1)
	if f.err != nil || f.status == nil {
		return nil, f.err
	}
	copyOfStatus := *f.status
	copyOfStatus.ClientScopes = append([]string(nil), f.status.ClientScopes...)
	copyOfStatus.ConsentScopes = append([]string(nil), f.status.ConsentScopes...)
	copyOfStatus.RBACStudentScopes = append([]string(nil), f.status.RBACStudentScopes...)
	return &copyOfStatus, nil
}

func newMCPExternalTokenFixture(t *testing.T) (
	MCPExternalTokenExchangeUsecase, *fakeMCPExternalCodeStore,
	*fakeMCPExternalGrantReadback, MCPExternalTokenRequest, time.Time,
) {
	t.Helper()
	codeUsecase, store, policy, request, client, consent, student, now := newMCPCodeFixture(t)
	code, err := codeUsecase.Issue(context.Background(), policy, request, client, consent, student, now)
	if err != nil {
		t.Fatal(err)
	}
	status := &domain.MCPExternalTokenGrantStatus{
		StudentID:         student,
		ClientID:          client.ID,
		ConsentID:         consent.ID,
		ResourceURI:       policy.ResourceURI,
		StudentActive:     true,
		ClientActive:      true,
		ConsentActive:     true,
		RBACStudentActive: true,
		ConsentExpiresAt:  consent.ExpiresAt,
		ClientScopes:      []string{"courses:read", "lessons:read", "tasks:read"},
		ConsentScopes:     []string{"courses:read", "lessons:read"},
		RBACStudentScopes: []string{"courses:read", "lessons:read"},
	}
	readback := &fakeMCPExternalGrantReadback{status: status}
	u := MCPExternalTokenExchangeUsecase{
		Codes:  store,
		Grants: readback,
		Policy: MCPExternalTokenPolicy{
			Issuer:               "https://auth.example.test/oauth",
			ResourceURI:          policy.ResourceURI,
			AllowedStudentScopes: []string{"courses:read", "lessons:read"},
			AccessTTL:            5 * time.Minute,
		},
	}
	return u, store, readback, MCPExternalTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		Verifier:    rfc7636Verifier,
		ClientID:    client.ID,
		RedirectURI: request.RedirectURI,
		ResourceURI: policy.ResourceURI,
	}, now
}

func TestMCPExternalTokenExchangeProducesOnlyBoundIntent(t *testing.T) {
	u, store, readback, request, now := newMCPExternalTokenFixture(t)
	intent, err := u.Prepare(context.Background(), request, now.Add(time.Second))
	if err != nil || intent == nil {
		t.Fatalf("valid code denied: intent=%+v err=%v", intent, err)
	}
	if !store.consumed || readback.calls.Load() != 1 {
		t.Fatal("fresh grant readback must follow exactly one code consumption")
	}
	if intent.Issuer != u.Policy.Issuer || intent.Subject != readback.status.StudentID ||
		intent.Audience != u.Policy.ResourceURI || intent.ClientID != request.ClientID ||
		intent.GrantID != readback.status.ConsentID ||
		intent.Scope != "courses:read lessons:read" ||
		intent.IssuedAt != now.Add(time.Second).Unix() ||
		intent.ExpiresAt != now.Add(time.Second).Add(5*time.Minute).Unix() ||
		!validMCPAuthorizationCode(intent.JWTID) {
		t.Fatalf("incorrect or unsafe access-token intent: %+v", intent)
	}
	if MCPExternalAccessTokenJOSEType != "at+jwt" {
		t.Fatalf("JOSE token type must be at+jwt, got %q", MCPExternalAccessTokenJOSEType)
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(encoded, &claims); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"iss", "sub", "aud", "client_id", "scope", "grant_id", "iat", "exp", "jti"} {
		if _, ok := claims[key]; !ok {
			t.Fatalf("missing access-token intent claim %q: %s", key, encoded)
		}
	}
	if len(claims) != 9 || strings.Contains(string(encoded), request.Code) ||
		strings.Contains(string(encoded), request.Verifier) ||
		strings.Contains(string(encoded), "refresh_token") {
		t.Fatalf("unexpected token fields or leaked secret: %s", encoded)
	}
	if again, err := u.Prepare(context.Background(), request, now.Add(2*time.Second)); again != nil || err != ErrMCPExternalDenied {
		t.Fatalf("replayed code accepted: intent=%+v err=%v", again, err)
	}
	if readback.calls.Load() != 1 {
		t.Fatal("replay must not read or reuse a prior grant")
	}
}

func TestMCPExternalTokenPreflightDeniesWithoutBurningCode(t *testing.T) {
	tests := []struct {
		name   string
		change func(*MCPExternalTokenExchangeUsecase, *MCPExternalTokenRequest, *time.Time)
	}{
		{"missing-code-store", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) { u.Codes = nil }},
		{"missing-grant-readback", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) { u.Grants = nil }},
		{"invalid-issuer", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) {
			u.Policy.Issuer = "http://auth.example.test"
		}},
		{"other-resource-policy", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) {
			u.Policy.ResourceURI = "https://another.example.test/mcp"
		}},
		{"zero-ttl", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) {
			u.Policy.AccessTTL = 0
		}},
		{"excessive-ttl", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) {
			u.Policy.AccessTTL = 6 * time.Minute
		}},
		{"empty-policy-scopes", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) {
			u.Policy.AllowedStudentScopes = nil
		}},
		{"duplicate-policy-scopes", func(u *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, _ *time.Time) {
			u.Policy.AllowedStudentScopes = []string{"courses:read", "courses:read"}
		}},
		{"implicit-grant", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) {
			r.GrantType = "implicit"
		}},
		{"refresh-grant", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) {
			r.GrantType = "refresh_token"
		}},
		{"request-scope-escalation", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) {
			r.Scope = "tasks:write"
		}},
		{"request-scope-even-if-allowed", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) {
			r.Scope = "courses:read"
		}},
		{"missing-code", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) { r.Code = "" }},
		{"missing-verifier", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) { r.Verifier = "" }},
		{"wrong-client", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) {
			r.ClientID = "foreign-client"
		}},
		{"wrong-redirect", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) {
			r.RedirectURI = "https://evil.test/callback"
		}},
		{"wrong-resource", func(_ *MCPExternalTokenExchangeUsecase, r *MCPExternalTokenRequest, _ *time.Time) {
			r.ResourceURI = "https://evil.test/mcp"
		}},
		{"missing-time", func(_ *MCPExternalTokenExchangeUsecase, _ *MCPExternalTokenRequest, now *time.Time) {
			*now = time.Time{}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, store, readback, req, now := newMCPExternalTokenFixture(t)
			tc.change(&u, &req, &now)
			intent, err := u.Prepare(context.Background(), req, now)
			if intent != nil || !errors.Is(err, ErrMCPExternalDenied) || store.consumed || readback.calls.Load() != 0 {
				t.Fatalf("unsafe preflight: intent=%+v err=%v consumed=%v readback=%d", intent, err, store.consumed, readback.calls.Load())
			}
		})
	}
}

func TestMCPExternalTokenFreshGrantRecheckDeniesAfterCodeConsumption(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeMCPExternalGrantReadback, time.Time)
	}{
		{"readback-error", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.err = errors.New("db down") }},
		{"missing-status", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status = nil }},
		{"student-deleted", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.StudentActive = false }},
		{"client-disabled", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.ClientActive = false }},
		{"consent-revoked", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.ConsentActive = false }},
		{"rbac-denied", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.RBACStudentActive = false }},
		{"rbac-scope-reduced", func(f *fakeMCPExternalGrantReadback, _ time.Time) {
			f.status.RBACStudentScopes = []string{"courses:read"}
		}},
		{"client-scope-reduced", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.ClientScopes = []string{"courses:read"} }},
		{"consent-scope-reduced", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.ConsentScopes = []string{"courses:read"} }},
		{"consent-expired", func(f *fakeMCPExternalGrantReadback, now time.Time) { f.status.ConsentExpiresAt = now }},
		{"different-student", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.StudentID = "student-B" }},
		{"different-client", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.ClientID = "client-B" }},
		{"different-consent", func(f *fakeMCPExternalGrantReadback, _ time.Time) {
			f.status.ConsentID = "22222222-2222-4222-8222-222222222222"
		}},
		{"different-resource", func(f *fakeMCPExternalGrantReadback, _ time.Time) { f.status.ResourceURI = "https://evil.test/mcp" }},
		{"too-short-consent", func(f *fakeMCPExternalGrantReadback, now time.Time) {
			f.status.ConsentExpiresAt = now.Add(time.Millisecond)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, store, readback, request, now := newMCPExternalTokenFixture(t)
			tc.change(readback, now)
			intent, err := u.Prepare(context.Background(), request, now)
			if intent != nil || err != ErrMCPExternalDenied || !store.consumed || readback.calls.Load() != 1 {
				t.Fatalf("unsafe grant check: intent=%+v err=%v consumed=%v readback=%d", intent, err, store.consumed, readback.calls.Load())
			}
		})
	}
}

func TestMCPExternalTokenExpiryCappedByConsent(t *testing.T) {
	u, _, readback, request, now := newMCPExternalTokenFixture(t)
	readback.status.ConsentExpiresAt = now.Add(90 * time.Second)
	intent, err := u.Prepare(context.Background(), request, now)
	if err != nil || intent == nil || intent.ExpiresAt != now.Add(90*time.Second).Unix() {
		t.Fatalf("access intent extended consent: intent=%+v err=%v", intent, err)
	}
}

func TestMCPExternalTokenConcurrentExchangeOneIntent(t *testing.T) {
	u, _, readback, request, now := newMCPExternalTokenFixture(t)
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if intent, err := u.Prepare(context.Background(), request, now); err == nil && intent != nil {
				ok.Add(1)
			} else if err != ErrMCPExternalDenied {
				t.Errorf("non-uniform denial: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || readback.calls.Load() != 1 {
		t.Fatalf("prepared=%d readback=%d, want one", ok.Load(), readback.calls.Load())
	}
}
