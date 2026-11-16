package domain

import "context"

// These signed assertions are distinct from an RBAC Student role ALLOW.
// Neither contract is registered in the running Auth service.
const (
	MCPStudentScopeProofAudience          = "ms-go-rbac-mcp-student-scopes"
	MCPStudentScopeProofType              = "mcp_student_scope_check"
	MCPStudentScopeProofPurpose           = "AUTH_RBAC_MCP_STUDENT_SCOPES_V1"
	MCPStudentScopeProofTTLSeconds        = 30
	MCPStudentScopeDecisionIssuer         = "ms-go-rbac"
	MCPStudentScopeDecisionAudience       = "ms-go-auth-mcp-student-scopes-decision"
	MCPStudentScopeDecisionType           = "mcp_student_scopes_decision"
	MCPStudentScopeDecisionPurpose        = "RBAC_AUTH_MCP_STUDENT_SCOPES_DECISION_V1"
	MCPStudentScopeDecisionMaxAgeSeconds  = 30
	MCPStudentScopeDecisionFutureSkewSecs = 5
	MCPStudentScopeLimit                  = 4
)

// ValidMCPStudentRequestedScopes admits only canonical read-only pilot scopes.
// It is a message grammar check, NOT a substitute for RBAC permission checks.
func ValidMCPStudentRequestedScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > MCPStudentScopeLimit {
		return false
	}
	previous := ""
	for _, scope := range scopes {
		if scope != "calendar:read" && scope != "courses:read" && scope != "profile:read" && scope != "tasks:read" {
			return false
		}
		if scope <= previous {
			return false
		}
		previous = scope
	}
	return true
}

// ValidMCPStudentAllowedScopes accepts only a non-nil sorted subset, including
// an explicitly signed empty result. Nil means RBAC never evaluated the scopes.
func ValidMCPStudentAllowedScopes(requested, allowed []string) bool {
	if !ValidMCPStudentRequestedScopes(requested) || allowed == nil || len(allowed) > len(requested) {
		return false
	}
	i := 0
	for _, scope := range allowed {
		for i < len(requested) && requested[i] < scope {
			i++
		}
		if i == len(requested) || requested[i] != scope {
			return false
		}
		i++
	}
	return true
}

// MCPStudentScopeDecisionClient consumes only an RBAC-signed subset bound to
// one fresh Auth proof, Student ID, request JTI, and exact requested scopes.
// Callers must treat an empty allowed slice as no entitlement.
type MCPStudentScopeDecisionClient interface {
	CheckMCPStudentScopes(ctx context.Context, signedAuthProof, expectedStudentID, requestJTI string, requestedScopes []string) ([]string, error)
}
