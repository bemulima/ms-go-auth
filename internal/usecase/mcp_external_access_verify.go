package usecase

import (
	"context"
	"time"

	"github.com/example/auth-service/internal/domain"
)

// MCPExternalVerifiedGrant is an Auth-side verified delegation for one MCP
// resource. The external bearer stays between MCP and its issuer Auth.
type MCPExternalVerifiedGrant struct {
	StudentID string   `json:"student_id"`
	ClientID  string   `json:"client_id"`
	GrantID   string   `json:"grant_id"`
	Audience  string   `json:"audience"`
	Scopes    []string `json:"scopes"`
	ExpiresAt int64    `json:"expires_at"`
}

// MCPExternalAccessVerification performs a fresh authenticated Auth/RBAC
// readback on EVERY accepted access, including a newly revoked consent.
// No cached Student role or consent, and no frontend JWT fallback.
type MCPExternalAccessVerification struct {
	Tokens *MCPExternalAccessJWTAuthority
	Grants domain.MCPExternalTokenGrantReadback
}

func (v MCPExternalAccessVerification) Verify(ctx context.Context, rawToken, resource string, now time.Time) (*MCPExternalVerifiedGrant, error) {
	if v.Tokens == nil || v.Grants == nil || ctx == nil || ctx.Err() != nil || now.IsZero() {
		return nil, ErrMCPExternalDenied
	}
	claims, err := v.Tokens.VerifySignature(rawToken, resource)
	if err != nil || ctx.Err() != nil {
		return nil, ErrMCPExternalDenied
	}
	snapshot, err := v.Grants.ReadbackMCPExternalTokenGrant(ctx, claims.Subject, claims.ClientID, claims.GrantID, resource, now.UTC())
	if err != nil || snapshot == nil || ctx.Err() != nil ||
		!snapshot.StudentActive || !snapshot.ClientActive || !snapshot.ConsentActive || !snapshot.RBACStudentActive ||
		snapshot.StudentID != claims.Subject || snapshot.ClientID != claims.ClientID ||
		snapshot.ConsentID != claims.GrantID || snapshot.ResourceURI != resource ||
		!snapshot.ConsentExpiresAt.After(now) {
		return nil, ErrMCPExternalDenied
	}
	scopes, valid := parseMCPRequestedScopes(claims.Scope)
	if !valid || !domain.ValidMCPStudentRequestedScopes(scopes) {
		return nil, ErrMCPExternalDenied
	}
	for _, scope := range scopes {
		if !hasMCPExactScope(snapshot.ClientScopes, scope) ||
			!hasMCPExactScope(snapshot.ConsentScopes, scope) ||
			!hasMCPExactScope(snapshot.RBACStudentScopes, scope) {
			return nil, ErrMCPExternalDenied
		}
	}
	expiry := time.Unix(claims.ExpiresAt, 0)
	if snapshot.ConsentExpiresAt.Before(expiry) {
		expiry = snapshot.ConsentExpiresAt
	}
	if !expiry.After(now) {
		return nil, ErrMCPExternalDenied
	}
	return &MCPExternalVerifiedGrant{
		StudentID: claims.Subject, ClientID: claims.ClientID, GrantID: claims.GrantID,
		Audience: resource, Scopes: append([]string(nil), scopes...), ExpiresAt: expiry.Unix(),
	}, nil
}
