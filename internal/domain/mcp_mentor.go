package domain

import (
	"context"
	"errors"
	"time"
)

const (
	MCPMentorScope            = "mentor:profile:read"
	MCPMentorOffersScope      = "mentor:offers:read"
	MCPMentorPersona          = "MENTOR"
	MCPMentorAccessType       = "mentor-at+jwt"
	MCPMentorRBACSubject      = "rbac.checkMCPMentorAccess"
	MCPMentorRBACAudience     = "ms-go-rbac-mcp-mentor"
	MCPMentorRBACPurpose      = "AUTH_RBAC_MCP_MENTOR_ACCESS_V1"
	MCPMentorDecisionAudience = "ms-go-auth-mcp-mentor-decision"
	MCPMentorDecisionPurpose  = "RBAC_AUTH_MCP_MENTOR_ACCESS_V1"
	MCPMentorOwnerAudience    = "ms-go-mentor-mcp"
	MCPMentorApprovalPurpose  = "MCP_MENTOR_APPROVAL_V1"
	MCPMentorProfilePurpose   = "MCP_MENTOR_PROFILE_READ_V1"
	MCPMentorOffersPurpose    = "MCP_MENTOR_OFFERS_READ_V1"
)

var (
	ErrMCPMentorDenied      = errors.New("MCP Mentor authorization denied")
	ErrMCPMentorUnavailable = errors.New("MCP Mentor authority unavailable")
)

type MCPMentorClient struct {
	ID, Name             string
	RedirectURIs, Scopes []string
}
type MCPMentorConsent struct {
	ID, MentorID, ClientID, Resource, Scope string
	ExpiresAt                               time.Time
}
type MCPMentorCode struct {
	Hash, MentorID, ClientID, ConsentID, RedirectURI, Resource, Challenge, Scope string
	ExpiresAt                                                                    time.Time
}

func ValidMCPMentorScope(scope string) bool {
	return scope == MCPMentorScope || scope == MCPMentorOffersScope
}

// Store never accesses Student MCP tables. Each grant has one exact scope.
type MCPMentorStore interface {
	Client(context.Context, string, string, string) (*MCPMentorClient, error)
	Consent(context.Context, string, string, string, string, time.Time) (*MCPMentorConsent, error)
	CreateGrant(context.Context, MCPMentorConsent, MCPMentorCode, time.Time) error
	ConsumeCode(context.Context, string, string, string, string, time.Time) (*MCPMentorCode, error)
	Revoke(context.Context, string, string, string) error
}
type MCPMentorRBACClient interface {
	CheckMCPMentorAccess(context.Context, string, string, string) (bool, error)
}
type MCPMentorApprovalClient interface {
	Approved(context.Context, string, string) error
}
