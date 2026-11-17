package domain

import (
	"context"
	"time"
)

// MCPExternalAuthorizationCode is a short-lived, audience-bound OAuth code.
// CodeHash is a SHA-256 digest of a CSPRNG code; the raw code never enters storage.
// It is independent of provider-login OAuthTransaction and RefreshToken.
type MCPExternalAuthorizationCode struct {
	CodeHash      string
	StudentID     string
	ClientID      string
	ConsentID     string
	RedirectURI   string
	ResourceURI   string
	CodeChallenge string
	Scopes        []string
	ExpiresAt     time.Time
}

// MCPExternalCodeRepository must enforce current persisted client/consent
// bindings on Create and atomically consume at most one unexpired code on
// Consume. A missing, revoked, used, or expired row returns ErrNotFound.
type MCPExternalCodeRepository interface {
	CreateMCPExternalCode(context.Context, *MCPExternalAuthorizationCode) error
	ConsumeMCPExternalCode(context.Context, string, string, string, string, time.Time) (*MCPExternalAuthorizationCode, error)
}
