package domain

import (
	"context"
	"time"
)

// MCPExternalAuthGrantSnapshot is only the fresh Auth-owned half of an
// external-token grant readback. A successful row means the Auth account is
// confirmed, the client is enabled, and the consent is active at read time.
// It carries NO RBAC assertion and must never be used as a token grant alone.
type MCPExternalAuthGrantSnapshot struct {
	StudentID        string
	ClientID         string
	ConsentID        string
	ResourceURI      string
	ConsentExpiresAt time.Time
	ClientScopes     []string
	ConsentScopes    []string
}

// MCPExternalAuthGrantReader owns the database-backed portion of the future
// combined MCPExternalTokenGrantReadback; an independent signed RBAC Student
// decision is still mandatory before token intent preparation.
type MCPExternalAuthGrantReader interface {
	ReadMCPExternalAuthGrant(context.Context, string, string, string, string, time.Time) (*MCPExternalAuthGrantSnapshot, error)
}

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
