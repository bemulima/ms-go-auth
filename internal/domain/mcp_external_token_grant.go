package domain

import (
	"context"
	"time"
)

// MCPExternalTokenGrantStatus is a fresh, trusted Auth/RBAC readback AFTER a
// one-use external authorization code has been consumed. No part of this
// status may be copied from token-request JSON, an MCP prompt, bearer headers
// or an earlier consent snapshot. This is not an HTTP DTO or token itself.
type MCPExternalTokenGrantStatus struct {
	StudentID         string
	ClientID          string
	ConsentID         string
	ResourceURI       string
	StudentActive     bool
	ClientActive      bool
	ConsentActive     bool
	RBACStudentActive bool
	ConsentExpiresAt  time.Time
	ClientScopes      []string
	ConsentScopes     []string
	RBACStudentScopes []string
}

// MCPExternalTokenGrantReadback is intentionally a missing implementation port.
// The future adapter must requery Auth-owned client/consent/account persistence
// and obtain a fresh, verified, signed RBAC Student authorization decision;
// any failed/unsigned readback must return an error. Never derive it from a
// code receipt alone or accept a client-supplied role/scope as the result.
type MCPExternalTokenGrantReadback interface {
	ReadbackMCPExternalTokenGrant(
		context.Context, string, string, string, string, time.Time,
	) (*MCPExternalTokenGrantStatus, error)
}
