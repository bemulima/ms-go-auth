package usecase

import (
	"context"
	"time"

	"github.com/example/auth-service/internal/domain"
)

// MCPExternalGrantComposer is the only composition candidate for a future
// external token exchange. A Student role decision is necessary but is never
// sufficient: every requested scope must separately be signed by RBAC.
// Its inputs are Auth-owned persistence and authenticated NATS ports only.
type MCPExternalGrantComposer struct {
	Reader               domain.MCPExternalAuthGrantReader
	RoleProofSigner      *MCPStudentRoleProofSigner
	RoleDecisions        domain.MCPStudentRoleDecisionClient
	ScopeProofSigner     *MCPStudentScopeProofSigner
	ScopeDecisions       domain.MCPStudentScopeDecisionClient
	AllowedStudentScopes []string
}

var _ domain.MCPExternalTokenGrantReadback = (*MCPExternalGrantComposer)(nil)

func (c *MCPExternalGrantComposer) ReadbackMCPExternalTokenGrant(
	ctx context.Context, studentID, clientID, consentID, resource string, now time.Time,
) (*domain.MCPExternalTokenGrantStatus, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || now.IsZero() ||
		c.Reader == nil || c.RoleProofSigner == nil || c.RoleDecisions == nil ||
		c.ScopeProofSigner == nil || c.ScopeDecisions == nil ||
		!domain.ValidMCPStudentRequestedScopes(c.AllowedStudentScopes) ||
		studentID == "" || clientID == "" || consentID == "" || resource == "" {
		return nil, ErrMCPExternalDenied
	}

	snapshot, err := c.Reader.ReadMCPExternalAuthGrant(ctx, studentID, clientID, consentID, resource, now.UTC())
	if err != nil || snapshot == nil || ctx.Err() != nil ||
		snapshot.StudentID != studentID || snapshot.ClientID != clientID ||
		snapshot.ConsentID != consentID || snapshot.ResourceURI != resource ||
		!snapshot.ConsentExpiresAt.After(now) {
		return nil, ErrMCPExternalDenied
	}

	roleProof, roleRequestID, err := c.RoleProofSigner.Sign(ctx, snapshot.StudentID)
	if err != nil || roleProof == "" || roleRequestID == "" || ctx.Err() != nil {
		return nil, ErrMCPExternalDenied
	}
	roleAllowed, err := c.RoleDecisions.CheckMCPStudentRole(ctx, roleProof, studentID, roleRequestID)
	if err != nil || !roleAllowed || ctx.Err() != nil {
		return nil, ErrMCPExternalDenied
	}

	// Platform, registered client and persisted consent intersect first. The
	// ordered subset is still only a REQUEST to RBAC, never a scope grant.
	requested := make([]string, 0, len(c.AllowedStudentScopes))
	for _, scope := range c.AllowedStudentScopes {
		if hasMCPExactScope(snapshot.ClientScopes, scope) && hasMCPExactScope(snapshot.ConsentScopes, scope) {
			requested = append(requested, scope)
		}
	}
	if !domain.ValidMCPStudentRequestedScopes(requested) {
		return nil, ErrMCPExternalDenied
	}
	scopeProof, scopeRequestID, err := c.ScopeProofSigner.Sign(ctx, snapshot, requested)
	if err != nil || scopeProof == "" || scopeRequestID == "" || ctx.Err() != nil {
		return nil, ErrMCPExternalDenied
	}
	allowed, err := c.ScopeDecisions.CheckMCPStudentScopes(ctx, scopeProof, studentID, scopeRequestID, requested)
	if err != nil || !domain.ValidMCPStudentAllowedScopes(requested, allowed) ||
		len(allowed) == 0 || ctx.Err() != nil {
		return nil, ErrMCPExternalDenied
	}

	return &domain.MCPExternalTokenGrantStatus{
		StudentID: studentID, ClientID: clientID, ConsentID: consentID, ResourceURI: resource,
		StudentActive: true, ClientActive: true, ConsentActive: true, RBACStudentActive: true,
		ConsentExpiresAt:  snapshot.ConsentExpiresAt,
		ClientScopes:      append([]string(nil), snapshot.ClientScopes...),
		ConsentScopes:     append([]string(nil), snapshot.ConsentScopes...),
		RBACStudentScopes: append([]string(nil), allowed...),
	}, nil
}
