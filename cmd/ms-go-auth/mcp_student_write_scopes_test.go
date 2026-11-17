package main

import (
	"reflect"
	"testing"

	"github.com/example/auth-service/internal/domain"
)

// Write grammar is not a grant. The default issuer ceiling stays V0 read only;
// client registration, stored Student consent and fresh RBAC checks remain
// required even when the operator explicitly widens the ceiling.
func TestMCP53MutationScopeCeilingIsSeparateAndDefaultOff(t *testing.T) {
	if !reflect.DeepEqual(approvedMCPStudentScopes(false), approvedMCPStudentReadScopes()) {
		t.Fatal("default MCP grant ceiling expanded without opt-in")
	}
	want := []string{
		"calendar:read", "courses:read", "instances:start", "profile:read",
		"submissions:write", "tasks:read", "validation:run", "workspace:write",
	}
	if !reflect.DeepEqual(approvedMCPStudentScopes(true), want) ||
		!domain.ValidMCPStudentRequestedScopes(want) {
		t.Fatalf("mutation-scope ceiling differs from canonical Auth/RBAC agreement: %#v", approvedMCPStudentScopes(true))
	}
	for _, invalid := range [][]string{
		{"instances:start", "instances:start"},
		{"workspace:write", "tasks:read"},
		{"teacher:ask"}, {"calendar:write"}, {"notifications:write"},
		{"courses:read", "courses:read"},
	} {
		if domain.ValidMCPStudentRequestedScopes(invalid) {
			t.Fatalf("unsafe or malformed MCP scopes admitted: %#v", invalid)
		}
	}
	previous := approvedMCPStudentScopes(true)
	previous[0] = "untrusted:write"
	if !reflect.DeepEqual(approvedMCPStudentScopes(true), want) {
		t.Fatal("mutable returned scope list contaminated platform policy")
	}
}
