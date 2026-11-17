package usecase

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
)

// MCPExternalAuthorizeUsecase completes a consent that Auth already persisted.
// It never creates consent from an external request or trusts a Student ID
// carried in an OAuth query, JSON body or gateway header.
type MCPExternalAuthorizeUsecase struct {
	Clients domain.MCPExternalClientConsentReader
	Grants  domain.MCPExternalTokenGrantReadback
	Codes   MCPExternalCodeUsecase
	Policy  MCPExternalPolicy
}

func (u MCPExternalAuthorizeUsecase) Authorize(ctx context.Context, request MCPExternalAuthorizationRequest,
	verifiedStudentID, state string, now time.Time) (string, error) {
	if ctx == nil || ctx.Err() != nil || u.Clients == nil || u.Grants == nil ||
		!validNonZeroCanonicalMCPUUID(verifiedStudentID) ||
		!validMCPExternalState(state) || now.IsZero() || request.ClientID == "" ||
		request.ResourceURI != u.Policy.ResourceURI {
		return "", ErrMCPExternalDenied
	}
	client, consent, err := u.Clients.ReadMCPExternalClientConsent(
		ctx, verifiedStudentID, request.ClientID, request.ResourceURI, now.UTC())
	if err != nil || client == nil || consent == nil || ctx.Err() != nil {
		return "", ErrMCPExternalDenied
	}
	registered := MCPExternalClient{ID: client.ClientID, RedirectURIs: client.RedirectURIs, AllowedScopes: client.AllowedScopes}
	approved := MCPExternalConsent{
		ID: consent.ID, StudentID: consent.StudentID, ClientID: consent.ClientID,
		ResourceURI: consent.ResourceURI, Scopes: consent.Scopes, ExpiresAt: consent.ExpiresAt,
	}
	requested, err := ValidateMCPExternalAuthorization(u.Policy, request, registered, approved, verifiedStudentID, now)
	if err != nil || !redirectQuerySafeForCode(request.RedirectURI) {
		return "", ErrMCPExternalDenied
	}
	// An Auth-persisted consent is necessary but cannot independently establish
	// the Student role or any requested scope. Ask RBAC for fresh signed proofs.
	grant, err := u.Grants.ReadbackMCPExternalTokenGrant(ctx, verifiedStudentID, request.ClientID,
		consent.ID, request.ResourceURI, now.UTC())
	if err != nil || grant == nil || ctx.Err() != nil ||
		!grant.StudentActive || !grant.ClientActive || !grant.ConsentActive || !grant.RBACStudentActive ||
		grant.StudentID != verifiedStudentID || grant.ClientID != request.ClientID ||
		grant.ConsentID != consent.ID || grant.ResourceURI != request.ResourceURI {
		return "", ErrMCPExternalDenied
	}
	for _, scope := range requested {
		if !hasMCPExactScope(grant.ClientScopes, scope) ||
			!hasMCPExactScope(grant.ConsentScopes, scope) ||
			!hasMCPExactScope(grant.RBACStudentScopes, scope) {
			return "", ErrMCPExternalDenied
		}
	}
	code, err := u.Codes.Issue(ctx, u.Policy, request, registered, approved, verifiedStudentID, now)
	if err != nil || ctx.Err() != nil {
		return "", ErrMCPExternalDenied
	}
	redirect, err := url.Parse(request.RedirectURI)
	if err != nil {
		return "", ErrMCPExternalDenied
	}
	params := redirect.Query()
	params.Set("code", code)
	params.Set("state", state)
	redirect.RawQuery = params.Encode()
	return redirect.String(), nil
}

func validMCPExternalState(state string) bool {
	if len(state) < 22 || len(state) > 256 {
		return false
	}
	for _, c := range state {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			continue
		}
		return false
	}
	return true
}

func redirectQuerySafeForCode(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !validMCPRedirectURI(raw) || strings.Contains(strings.ToLower(u.RawQuery), "%0d") ||
		strings.Contains(strings.ToLower(u.RawQuery), "%0a") {
		return false
	}
	query := u.Query()
	for _, key := range []string{"code", "state", "error", "access_token"} {
		if _, ok := query[key]; ok {
			return false
		}
	}
	return true
}
