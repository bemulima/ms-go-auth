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

func TestMCP53PrivateLearningScopesRequireSeparatePlatformOptIn(t *testing.T) {
	baseline := approvedMCPStudentReadScopeCeiling(false)
	if !reflect.DeepEqual(baseline, approvedMCPStudentReadScopes()) {
		t.Fatal("default issuer read ceiling changed")
	}
	want := []string{"calendar:read", "courses:read", "knowledge:read", "lessons:read", "profile:read", "tasks:read"}
	private := approvedMCPStudentReadScopeCeiling(true)
	if !reflect.DeepEqual(private, want) || !domain.ValidMCPStudentRequestedScopes(private) {
		t.Fatalf("unexpected private-only read scope ceiling: %#v", private)
	}
	combined := []string{"calendar:read", "courses:read", "instances:start", "knowledge:read",
		"lessons:read", "profile:read", "submissions:write", "tasks:read", "validation:run", "workspace:write"}
	if !reflect.DeepEqual(approvedMCPStudentScopeCeiling(true, true), combined) ||
		!domain.ValidMCPStudentRequestedScopes(combined) {
		t.Fatal("private scope opt-in was not composable with separate mutation opt-in")
	}
	if domain.ValidMCPStudentRequestedScopes([]string{"knowledge:write"}) ||
		domain.ValidMCPStudentRequestedScopes([]string{"lessons:write"}) ||
		domain.ValidMCPStudentRequestedScopes([]string{"courses:read", "knowledge:read", "knowledge:read"}) ||
		domain.ValidMCPStudentRequestedScopes([]string{"lessons:read", "knowledge:read"}) {
		t.Fatal("unknown, repeated or unordered content scope admitted")
	}
	private[2] = "teacher:ask"
	if !reflect.DeepEqual(approvedMCPStudentReadScopeCeiling(true), want) {
		t.Fatal("read policy returned a mutable globally shared scope slice")
	}
}
