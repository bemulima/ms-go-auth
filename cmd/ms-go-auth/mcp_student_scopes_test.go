package main

import (
	"reflect"
	"testing"

	"github.com/example/auth-service/internal/domain"
)

func TestMCP53PlatformReadScopesAreOnlyExplicitRBACPilot(t *testing.T) {
	want := []string{"courses:read", "profile:read", "tasks:read"}
	scopes := approvedMCPStudentReadScopes()
	if !reflect.DeepEqual(scopes, want) || !domain.ValidMCPStudentRequestedScopes(scopes) {
		t.Fatalf("platform scope ceiling does not match exact Auth/RBAC pilot: %#v", scopes)
	}
	for _, forbidden := range []string{"instances:start", "submissions:write", "workspace:write", "calendar:read", "teacher:ask", "instances:read"} {
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
