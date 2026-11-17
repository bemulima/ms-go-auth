package domain

import "context"

const (
	MCPStudentRole                       = "student"
	MCPStudentRoleProofAudience          = "ms-go-rbac-mcp-student-role"
	MCPStudentRoleProofType              = "mcp_student_role_check"
	MCPStudentRoleProofPurpose           = "AUTH_RBAC_MCP_STUDENT_ROLE_V1"
	MCPStudentRoleProofTTLSeconds        = 30
	MCPStudentRoleDecisionIssuer         = "ms-go-rbac"
	MCPStudentRoleDecisionAudience       = "ms-go-auth-mcp-student-role-decision"
	MCPStudentRoleDecisionType           = "mcp_student_role_decision"
	MCPStudentRoleDecisionPurpose        = "RBAC_AUTH_MCP_STUDENT_ROLE_DECISION_V1"
	MCPStudentRoleDecisionMaxAgeSeconds  = 30
	MCPStudentRoleDecisionFutureSkewSecs = 5
)

// MCPStudentRoleDecisionClient verifies a fresh, request-bound, signed RBAC
// decision about the Student role only. ALLOW carries no MCP scope entitlement.
// The future token-grant composer must separately establish RBAC scope policy.
type MCPStudentRoleDecisionClient interface {
	CheckMCPStudentRole(ctx context.Context, signedAuthProof, expectedStudentID, requestJTI string) (bool, error)
}
