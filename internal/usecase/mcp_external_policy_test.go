package usecase

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestMCPExternalPKCES256RFC7636Vector(t *testing.T) {
	if err := VerifyMCPExternalPKCES256(rfc7636Verifier, rfc7636Challenge); err != nil {
		t.Fatalf("RFC 7636 S256 vector rejected: %v", err)
	}

	for _, tc := range []struct {
		name      string
		verifier  string
		challenge string
	}{
		{"short-verifier", "short", rfc7636Challenge},
		{"unicode-verifier", strings.Repeat("я", 43), rfc7636Challenge},
		{"space-verifier", strings.Repeat("a", 42) + " ", rfc7636Challenge},
		{"wrong-verifier", strings.Repeat("a", 43), rfc7636Challenge},
		{"wrong-challenge", rfc7636Verifier, strings.Repeat("A", 43)},
		{"padding-not-allowed", rfc7636Verifier, rfc7636Challenge + "="},
		{"too-long-verifier", strings.Repeat("a", 129), rfc7636Challenge},
		{"invalid-challenge-charset", rfc7636Verifier, strings.Repeat("!", 43)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyMCPExternalPKCES256(tc.verifier, tc.challenge); err != ErrMCPExternalDenied {
				t.Fatalf("err=%v; want uniform denial", err)
			}
		})
	}
}

func baseMCPExternalFixture() (
	MCPExternalPolicy,
	MCPExternalAuthorizationRequest,
	MCPExternalClient,
	MCPExternalConsent,
	string,
	time.Time,
) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	resource := "https://mcp.example.test/mcp"
	student := "student-A"
	client := MCPExternalClient{
		ID:            "https://client.example.test/metadata.json",
		RedirectURIs:  []string{"https://client.example.test/callback", "http://127.0.0.1:4567/callback"},
		AllowedScopes: []string{"courses:read", "lessons:read", "tasks:read", "instances:start"},
	}
	consent := MCPExternalConsent{
		StudentID:   student,
		ClientID:    client.ID,
		ResourceURI: resource,
		Scopes:      []string{"courses:read", "lessons:read"},
		ExpiresAt:   now.Add(time.Hour),
	}
	request := MCPExternalAuthorizationRequest{
		ResponseType:        "code",
		ClientID:            client.ID,
		RedirectURI:         "https://client.example.test/callback",
		ResourceURI:         resource,
		CodeChallenge:       rfc7636Challenge,
		CodeChallengeMethod: "S256",
		Scope:               "courses:read lessons:read",
	}
	policy := MCPExternalPolicy{
		ResourceURI:          resource,
		AllowedStudentScopes: []string{"courses:read", "lessons:read", "tasks:read"},
	}
	return policy, request, client, consent, student, now
}

func TestMCPExternalAuthorizationOnlyExplicitConsentedScopes(t *testing.T) {
	policy, request, client, consent, student, now := baseMCPExternalFixture()
	scopes, err := ValidateMCPExternalAuthorization(policy, request, client, consent, student, now)
	if err != nil {
		t.Fatalf("valid explicit Student consent rejected: %v", err)
	}
	if !reflect.DeepEqual(scopes, []string{"courses:read", "lessons:read"}) {
		t.Fatalf("scopes=%q", scopes)
	}

	// An exactly registered loopback redirect may be admitted for a native
	// client, without generalizing to an unregistered port or hostname.
	request.RedirectURI = "http://127.0.0.1:4567/callback"
	if _, err := ValidateMCPExternalAuthorization(policy, request, client, consent, student, now); err != nil {
		t.Fatalf("registered loopback redirect rejected: %v", err)
	}
}

func TestMCPExternalAuthorizationFailClosedMatrix(t *testing.T) {
	tests := []struct {
		name   string
		change func(*MCPExternalPolicy, *MCPExternalAuthorizationRequest, *MCPExternalClient, *MCPExternalConsent, *string, *time.Time)
	}{
		{"anonymous-subject", func(_ *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, student *string, _ *time.Time) {
			*student = ""
		}},
		{"response-type-token", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.ResponseType = "token"
		}},
		{"different-client", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.ClientID = "unregistered"
		}},
		{"redirect-prefix-attack", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.RedirectURI += ".evil.test"
		}},
		{"redirect-host-prefix-attack", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.RedirectURI = "https://client.example.test.evil.test/callback"
		}},
		{"redirect-fragment", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.RedirectURI += "#fragment"
		}},
		{"unregistered-loopback-port", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.RedirectURI = "http://127.0.0.1:4568/callback"
		}},
		{"unsafe-localhost", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, c *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.RedirectURI = "http://localhost:4567/callback"
			c.RedirectURIs = append(c.RedirectURIs, r.RedirectURI)
		}},
		{"http-remote-redirect", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, c *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.RedirectURI = "http://client.example.test/callback"
			c.RedirectURIs = append(c.RedirectURIs, r.RedirectURI)
		}},
		{"wrong-audience", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.ResourceURI = "https://another.example.test/mcp"
		}},
		{"wrong-policy-resource", func(p *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			p.ResourceURI = "http://mcp.example.test/mcp"
		}},
		{"resource-query", func(p *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, c *MCPExternalConsent, _ *string, _ *time.Time) {
			p.ResourceURI += "?x=1"
			r.ResourceURI = p.ResourceURI
			c.ResourceURI = p.ResourceURI
		}},
		{"plain-pkce", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.CodeChallengeMethod = "plain"
		}},
		{"missing-pkce", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.CodeChallenge = ""
		}},
		{"missing-scopes", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.Scope = ""
		}},
		{"duplicate-scopes", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.Scope = "courses:read courses:read"
		}},
		{"wildcard-scope", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.Scope = "*"
		}},
		{"client-scope-not-allowed", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, c *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.Scope = "courses:read"
			c.AllowedScopes = []string{"tasks:read"}
		}},
		{"role-policy-scope-not-allowed", func(p *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			p.AllowedStudentScopes = []string{"tasks:read"}
		}},
		{"newline-scope", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.Scope = "courses:read\nlessons:read"
		}},
		{"consent-scope-not-granted", func(_ *MCPExternalPolicy, r *MCPExternalAuthorizationRequest, _ *MCPExternalClient, _ *MCPExternalConsent, _ *string, _ *time.Time) {
			r.Scope = "tasks:read"
		}},
		{"no-consent", func(_ *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, c *MCPExternalConsent, _ *string, _ *time.Time) {
			c.Scopes = nil
		}},
		{"revoked-consent", func(_ *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, c *MCPExternalConsent, _ *string, _ *time.Time) {
			c.Revoked = true
		}},
		{"expired-consent", func(_ *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, c *MCPExternalConsent, _ *string, now *time.Time) {
			c.ExpiresAt = *now
		}},
		{"other-student-consent", func(_ *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, c *MCPExternalConsent, _ *string, _ *time.Time) {
			c.StudentID = "student-B"
		}},
		{"other-client-consent", func(_ *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, c *MCPExternalConsent, _ *string, _ *time.Time) {
			c.ClientID = "client-B"
		}},
		{"other-resource-consent", func(_ *MCPExternalPolicy, _ *MCPExternalAuthorizationRequest, _ *MCPExternalClient, c *MCPExternalConsent, _ *string, _ *time.Time) {
			c.ResourceURI = "https://other.example.test/mcp"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r, client, consent, student, now := baseMCPExternalFixture()
			tc.change(&p, &r, &client, &consent, &student, &now)
			scopes, err := ValidateMCPExternalAuthorization(p, r, client, consent, student, now)
			if err != ErrMCPExternalDenied || scopes != nil {
				t.Fatalf("scopes=%q err=%v; want uniform fail-closed rejection", scopes, err)
			}
		})
	}
}
