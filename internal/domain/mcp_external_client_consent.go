package domain

import (
	"context"
	"time"
)

type MCPExternalClientRegistration struct {
	ClientID      string
	RedirectURIs  []string
	AllowedScopes []string
}

type MCPExternalStoredConsent struct {
	ID          string
	StudentID   string
	ClientID    string
	ResourceURI string
	Scopes      []string
	ExpiresAt   time.Time
}

// MCPExternalClientConsentReader reads the persisted, approved Auth client
// and a current Student-owned consent. It never creates consent on request.
type MCPExternalClientConsentReader interface {
	ReadMCPExternalClientConsent(
		context.Context, string, string, string, time.Time,
	) (*MCPExternalClientRegistration, *MCPExternalStoredConsent, error)
}

// MCPExternalConsentRevoker revokes only Auth-owned consent for the trusted
// session Student. A deleted/unknown consent is indistinguishable from an
// already-revoked consent to the untrusted caller.
type MCPExternalConsentRevoker interface {
	RevokeMCPExternalConsent(context.Context, string, string, string) error
}
