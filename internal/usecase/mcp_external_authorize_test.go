package usecase

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
)

type fakeMCPClientConsent struct {
	client  *domain.MCPExternalClientRegistration
	consent *domain.MCPExternalStoredConsent
	err     error
}

func (f *fakeMCPClientConsent) ReadMCPExternalClientConsent(_ context.Context, _, _, _ string, _ time.Time) (*domain.MCPExternalClientRegistration, *domain.MCPExternalStoredConsent, error) {
	return f.client, f.consent, f.err
}

func authorizeFixture(t *testing.T) (MCPExternalAuthorizeUsecase, *fakeMCPExternalGrantReadback, MCPExternalAuthorizationRequest, string, time.Time) {
	t.Helper()
	codes, _, policy, req, client, consent, student, now := newMCPCodeFixture(t)
	student = "00000000-0000-4000-8000-000000000123"
	consent.StudentID = student
	req.Scope = "courses:read"
	policy.AllowedStudentScopes = []string{"courses:read"}
	reader := &fakeMCPClientConsent{
		client: &domain.MCPExternalClientRegistration{
			ClientID: client.ID, RedirectURIs: client.RedirectURIs,
			AllowedScopes: client.AllowedScopes,
		},
		consent: &domain.MCPExternalStoredConsent{
			ID: consent.ID, StudentID: student, ClientID: client.ID,
			ResourceURI: policy.ResourceURI, Scopes: consent.Scopes, ExpiresAt: consent.ExpiresAt,
		},
	}
	grants := &fakeMCPExternalGrantReadback{status: &domain.MCPExternalTokenGrantStatus{
		StudentID: student, ClientID: client.ID, ConsentID: consent.ID,
		ResourceURI: policy.ResourceURI, StudentActive: true, ClientActive: true,
		ConsentActive: true, RBACStudentActive: true,
		ConsentExpiresAt: consent.ExpiresAt,
		ClientScopes:     client.AllowedScopes, ConsentScopes: consent.Scopes,
		RBACStudentScopes: []string{"courses:read"},
	}}
	return MCPExternalAuthorizeUsecase{Clients: reader, Grants: grants, Codes: codes, Policy: policy}, grants, req, student, now
}

func TestMCPExternalAuthorizeIssuesOnlyForFreshRBACApprovedStudent(t *testing.T) {
	u, grants, req, student, now := authorizeFixture(t)
	state := strings.Repeat("A", 32)
	callback, err := u.Authorize(context.Background(), req, student, state, now)
	if err != nil {
		t.Fatal(err)
	}
	location, err := url.Parse(callback)
	if err != nil || location.Scheme != "https" || location.Host == "" ||
		location.Query().Get("state") != state || !validMCPAuthorizationCode(location.Query().Get("code")) {
		t.Fatalf("invalid registered callback: %s (%v)", callback, err)
	}
	if grants.calls.Load() != 1 {
		t.Fatal("fresh signed RBAC readback required on issuance")
	}
}

func TestMCPExternalAuthorizeDeniesBadStateAndMissingRBACScopes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*MCPExternalAuthorizeUsecase, *MCPExternalAuthorizationRequest, *fakeMCPExternalGrantReadback, *string)
	}{
		{"low-entropy-state", func(_ *MCPExternalAuthorizeUsecase, _ *MCPExternalAuthorizationRequest, _ *fakeMCPExternalGrantReadback, s *string) {
			*s = "abc"
		}},
		{"rbac-no-scope", func(_ *MCPExternalAuthorizeUsecase, _ *MCPExternalAuthorizationRequest, g *fakeMCPExternalGrantReadback, _ *string) {
			g.status.RBACStudentScopes = []string{}
		}},
		{"rbac-unavailable", func(_ *MCPExternalAuthorizeUsecase, _ *MCPExternalAuthorizationRequest, g *fakeMCPExternalGrantReadback, _ *string) {
			g.err = errors.New("broker unavailable")
		}},
		{"client-mismatch", func(_ *MCPExternalAuthorizeUsecase, r *MCPExternalAuthorizationRequest, _ *fakeMCPExternalGrantReadback, _ *string) {
			r.ClientID = "other-client"
		}},
		{"redirect-unregistered", func(_ *MCPExternalAuthorizeUsecase, r *MCPExternalAuthorizationRequest, _ *fakeMCPExternalGrantReadback, _ *string) {
			r.RedirectURI = "https://attacker.test/cb"
		}},
		{"callback-query-conflict", func(u *MCPExternalAuthorizeUsecase, r *MCPExternalAuthorizationRequest, _ *fakeMCPExternalGrantReadback, _ *string) {
			r.RedirectURI += "?state=spoof"
			u.Clients.(*fakeMCPClientConsent).client.RedirectURIs = []string{r.RedirectURI}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, g, r, student, now := authorizeFixture(t)
			state := strings.Repeat("A", 32)
			tc.change(&u, &r, g, &state)
			if redirect, err := u.Authorize(context.Background(), r, student, state, now); redirect != "" || err != ErrMCPExternalDenied {
				t.Fatalf("unsafe code authorization: redirect=%q err=%v", redirect, err)
			}
		})
	}
}
