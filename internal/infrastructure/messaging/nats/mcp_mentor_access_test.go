package natsadapter

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
)

func mcpMentorDecisionFixture(now time.Time) (string, map[string]any) {
	request := map[string]any{"iss": "https://api.example.test/mentor", "aud": domain.MCPMentorRBACAudience, "sub": mcpDecisionTestStudent, "persona": "MENTOR", "purpose": domain.MCPMentorRBACPurpose, "scope": domain.MCPMentorScope, "jti": mcpDecisionTestRequest, "iat": now.Unix(), "exp": now.Unix() + 15}
	body, _ := json.Marshal(request)
	proof := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body) + ".c2lnbmF0dXJl"
	digest := sha256.Sum256([]byte(proof))
	return proof, map[string]any{"iss": "ms-go-rbac", "aud": domain.MCPMentorDecisionAudience, "sub": mcpDecisionTestStudent, "persona": "MENTOR", "purpose": domain.MCPMentorDecisionPurpose, "scope": domain.MCPMentorScope, "jti": mcpDecisionTestReply, "iat": now.Unix(), "exp": now.Unix() + 15, "active": true, "allowed": true, "request_jti": mcpDecisionTestRequest, "request_digest": hex.EncodeToString(digest[:])}
}
func TestMCPMentorRBACClientRequiresSignedFreshNonceAndPermissionDecision(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	public, err := parseReviewerPermissionDecisionPublicKey(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name                  string
		active, allowed, want bool
	}{{"approved permission", true, true, true}, {"role without permission", true, false, false}, {"no role", false, false, false}} {
		t.Run(test.name, func(t *testing.T) {
			proof, claims := mcpMentorDecisionFixture(now)
			claims["active"] = test.active
			claims["allowed"] = test.allowed
			raw := signReviewerDecisionForTest(t, key, claims)
			requester := &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + raw + `"}`)}
			client := &mcpMentorRBACClient{conn: requester, key: public, now: func() time.Time { return now }, used: map[string]int64{}}
			allowed, err := client.CheckMCPMentorAccess(context.Background(), proof, mcpDecisionTestStudent, mcpDecisionTestRequest)
			if err != nil || allowed != test.want || requester.subject != domain.MCPMentorRBACSubject {
				t.Fatalf("decision=%v err=%v", allowed, err)
			}
			if _, err = client.CheckMCPMentorAccess(context.Background(), proof, mcpDecisionTestStudent, mcpDecisionTestRequest); err != domain.ErrMCPMentorUnavailable {
				t.Fatal("signed response replay accepted")
			}
		})
	}
}
func TestMCPMentorRBACClientRejectsSignedWrongBindingsAndUnsignedAllow(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	public, err := parseReviewerPermissionDecisionPublicKey(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for name, edit := range map[string]func(map[string]any){
		"Student persona":         func(c map[string]any) { c["persona"] = "STUDENT" },
		"Student scope":           func(c map[string]any) { c["scope"] = "profile:read" },
		"wrong audience":          func(c map[string]any) { c["aud"] = domain.MCPStudentScopeDecisionAudience },
		"role proof substitution": func(c map[string]any) { c["purpose"] = domain.MCPStudentRoleDecisionPurpose },
		"wrong subject":           func(c map[string]any) { c["sub"] = "30000000-0000-4000-8000-000000000001" },
		"wrong nonce":             func(c map[string]any) { c["request_jti"] = "40000000-0000-4000-8000-000000000001" },
		"wrong digest":            func(c map[string]any) { c["request_digest"] = strings.Repeat("0", 64) },
		"permission without role": func(c map[string]any) { c["active"] = false },
		"expired":                 func(c map[string]any) { c["exp"] = now.Unix() },
		"reply beyond proof":      func(c map[string]any) { c["exp"] = now.Unix() + 16 },
		"extra grant":             func(c map[string]any) { c["roles"] = []string{"mentor"} },
	} {
		t.Run(name, func(t *testing.T) {
			proof, claims := mcpMentorDecisionFixture(now)
			edit(claims)
			raw := signReviewerDecisionForTest(t, key, claims)
			client := &mcpMentorRBACClient{conn: &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + raw + `"}`)}, key: public, now: func() time.Time { return now }, used: map[string]int64{}}
			if allowed, err := client.CheckMCPMentorAccess(context.Background(), proof, mcpDecisionTestStudent, mcpDecisionTestRequest); err != domain.ErrMCPMentorUnavailable || allowed {
				t.Fatal("unbound decision accepted")
			}
		})
	}
	proof, _ := mcpMentorDecisionFixture(now)
	client := &mcpMentorRBACClient{conn: &mcpStudentRoleReplyRequester{reply: []byte(`{"allowed":true}`)}, key: public, now: func() time.Time { return now }, used: map[string]int64{}}
	if allowed, err := client.CheckMCPMentorAccess(context.Background(), proof, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed {
		t.Fatal("unsigned ALLOW accepted")
	}
}
