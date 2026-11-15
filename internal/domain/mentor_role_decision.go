package domain

import "context"

const (
	MentorRoleDecisionIssuer     = "ms-go-auth"
	MentorRoleDecisionAudience   = "ms-go-rbac-mentor-role"
	MentorRoleDecisionType       = "mentor_role_decision"
	MentorRoleDecisionPurpose    = "AUTH_RBAC_MENTOR_ROLE_DECISION_V1"
	MentorRoleDecisionRole       = "mentor"
	MentorRoleDecisionService    = "ms-go-mentor"
	MentorRoleDecisionTTLSeconds = int64(30)
	MentorRoleDecisionMaxBytes   = 8192
	MentorRoleDecisionMaxInteger = int64(9007199254740991)
	MentorApprovalPendingGrant   = "APPROVAL_PENDING_GRANT"
	MentorSuspended              = "SUSPENDED"
)

// MentorRoleDecisionRequest selects one immutable Mentor-owned command. Actor,
// role and scope are deliberately absent: none can be chosen by this caller.
type MentorRoleDecisionRequest struct {
	TargetUserID        string
	ApplicationID       string
	ApplicationRevision int64
	Decision            string
	RequestID           string
	DecisionDigest      string
}

// MentorRoleDecisionBinding includes only the actor derived from a live Auth
// session. It must exactly match the committed current Mentor decision intent.
type MentorRoleDecisionBinding struct {
	MentorRoleDecisionRequest
	AdminActorID string
}

type CanonicalAdminConfirmation struct {
	ActorID                     string
	UniqueCanonicalDefaultAdmin bool
}

// CanonicalAdminVerifier is an authenticated RBAC-owner boundary, not the legacy
// role lookup (which permits scope fallback). Implementations must check exactly
// one current canonical-default Admin assignment for the supplied actor. A
// cached actor ID, access-token role claim or unsigned RPC response is not proof.
// No production adapter is supplied by this source-only contract.
type CanonicalAdminVerifier interface {
	ConfirmCanonicalAdmin(context.Context, string) (*CanonicalAdminConfirmation, error)
}

type MentorCommittedIntentConfirmation struct {
	Binding   MentorRoleDecisionBinding
	Committed bool
	Current   bool
	State     string
}

// MentorCommittedIntentVerifier is an authenticated Mentor-owner boundary.
// APPROVE must match the current pending RBAC intent at revision 2; SUSPEND the
// current suspended intent at revision 3 or 4. Confirmation must bind every
// field, including target and the live actor. Unknown/stale decisions deny.
// Transport authentication and fresh response binding are adapter obligations;
// no plain unsigned or cached confirmation may implement this authority.
type MentorCommittedIntentVerifier interface {
	ConfirmCommittedMentorIntent(context.Context, MentorRoleDecisionBinding) (*MentorCommittedIntentConfirmation, error)
}
