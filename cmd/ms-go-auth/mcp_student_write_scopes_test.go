package main

import (
	"reflect"
	"strings"
	"time"

	"github.com/example/auth-service/internal/usecase"
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

func TestMCP53AuthorizePolicyUsesSameExplicitScopeCeilingAsTokenExchange(t *testing.T) {
	const resource = "https://mcp.example.test/mcp"
	const clientID = "https://external-client.example.test/metadata.json"
	const redirect = "https://external-client.example.test/callback"
	const student = "student-A"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		mutations    bool
		privateReads bool
		scope        string
		wantAllowed  bool
	}{
		{name: "default-read-only-denies-start", scope: "instances:start"},
		{name: "private-only-denies-start", privateReads: true, scope: "instances:start"},
		{name: "write-enabled-allows-start-with-exact-consent", mutations: true, scope: "instances:start", wantAllowed: true},
		{name: "write-enabled-allows-save-with-exact-consent", mutations: true, scope: "workspace:write", wantAllowed: true},
		{name: "write-enabled-allows-submit-with-exact-consent", mutations: true, scope: "submissions:write", wantAllowed: true},
		{name: "write-enabled-allows-validation-with-exact-consent", mutations: true, scope: "validation:run", wantAllowed: true},
		{name: "private-learning-scope-still-default-off", mutations: true, scope: "lessons:read"},
		{name: "private-scope-explicit-opt-in", mutations: true, privateReads: true, scope: "lessons:read", wantAllowed: true},
		{name: "combined-guided-read-and-start", mutations: true, scope: "courses:read instances:start tasks:read", wantAllowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scopes := approvedMCPStudentScopeCeiling(tc.mutations, tc.privateReads)
			policy := authorizePolicyForMCPStudent(resource, scopes)
			if !reflect.DeepEqual(policy.AllowedStudentScopes, scopes) {
				t.Fatal("authorization and token exchange scope ceilings diverged")
			}
			client := usecase.MCPExternalClient{ID: clientID, RedirectURIs: []string{redirect}, AllowedScopes: append([]string(nil), scopes...)}
			consent := usecase.MCPExternalConsent{
				StudentID: student, ClientID: clientID, ResourceURI: resource,
				Scopes: []string{"courses:read", "instances:start", "lessons:read", "submissions:write", "tasks:read", "validation:run", "workspace:write"},
				ExpiresAt: now.Add(time.Hour),
			}
			request := usecase.MCPExternalAuthorizationRequest{
				ResponseType: "code", ClientID: clientID, RedirectURI: redirect,
				ResourceURI: resource, CodeChallenge: challenge, CodeChallengeMethod: "S256",
				Scope: tc.scope,
			}
			got, err := usecase.ValidateMCPExternalAuthorization(policy, request, client, consent, student, now)
			if tc.wantAllowed && (err != nil || !reflect.DeepEqual(got, strings.Split(tc.scope, " "))) {
				t.Fatalf("explicitly consented scope denied: err=%v scopes=%v", err, got)
			}
			if !tc.wantAllowed && (err != usecase.ErrMCPExternalDenied || got != nil) {
				t.Fatalf("unqualified request admitted: err=%v scopes=%v", err, got)
			}
			// A client-scopes or consent omission must never be bypassed by
			// the platform's expanded operator ceiling.
			if tc.wantAllowed {
				client.AllowedScopes = nil
				if _, err := usecase.ValidateMCPExternalAuthorization(policy, request, client, consent, student, now); err != usecase.ErrMCPExternalDenied {
					t.Fatal("client scope omission admitted")
				}
				client.AllowedScopes = append([]string(nil), scopes...)
				consent.Scopes = nil
				if _, err := usecase.ValidateMCPExternalAuthorization(policy, request, client, consent, student, now); err != usecase.ErrMCPExternalDenied {
					t.Fatal("missing Student consent admitted")
				}
			}
			policy.AllowedStudentScopes[0] = "untrusted:write"
			if !reflect.DeepEqual(scopes, approvedMCPStudentScopeCeiling(tc.mutations, tc.privateReads)) {
				t.Fatal("authorization policy may mutate exchange ceiling")
			}
		})
	}
}
