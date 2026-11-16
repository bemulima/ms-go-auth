package main

import (
	"reflect"
	"testing"

	"github.com/example/auth-service/internal/domain"
)

func TestMCP53PlatformReadScopesAreOnlyExplicitRBACPilot(t *testing.T) {
	want := []string{"calendar:read", "courses:read", "profile:read", "tasks:read"}
	scopes := approvedMCPStudentReadScopes()
	if !reflect.DeepEqual(scopes, want) || !domain.ValidMCPStudentRequestedScopes(scopes) {
		t.Fatalf("platform scope ceiling does not match exact Auth/RBAC pilot: %#v", scopes)
	}
	for _, forbidden := range []string{"instances:start", "submissions:write", "workspace:write", "calendar:write", "teacher:ask", "instances:read"} {
		for _, allowed := range scopes {
			if allowed == forbidden {
				t.Fatalf("unqualified scope %s admitted to pilot", forbidden)
			}
		}
	}
	// Do not return a package-global mutable slice shared by sessions.
	scopes[0] = "untrusted:write"
	if !reflect.DeepEqual(approvedMCPStudentReadScopes(), want) {
		t.Fatal("mutable previous caller scope value contaminated issuer policy")
	}
}

func TestMCP53CalendarScopeHasNoImpliedGrantToOtherScopes(t *testing.T) {
	if !domain.ValidMCPStudentRequestedScopes([]string{"calendar:read"}) ||
		!domain.ValidMCPStudentRequestedScopes([]string{"calendar:read", "courses:read", "profile:read", "tasks:read"}) {
		t.Fatal("explicit sorted Calendar read must be admissible by the grammar")
	}
	for _, unsupported := range [][]string{
		{"calendar:write"}, {"calendar:read", "calendar:read"},
		{"courses:read", "calendar:read"}, {"calendar:read", "courses:read", "profile:read", "tasks:read", "teacher:ask"},
	} {
		if domain.ValidMCPStudentRequestedScopes(unsupported) {
			t.Fatalf("invalid privilege set accepted: %v", unsupported)
		}
	}
	if !domain.ValidMCPStudentAllowedScopes([]string{"calendar:read"}, []string{}) ||
		domain.ValidMCPStudentAllowedScopes([]string{"calendar:read"}, []string{"courses:read"}) {
		t.Fatal("RBAC-signed scope subset cannot be implied by consent")
	}
}
