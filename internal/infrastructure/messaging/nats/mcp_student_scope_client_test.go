package natsadapter

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
)

const mcpScopeDecisionTestProof = "synthetic-auth-signed-student-scope-proof"

var mcpScopeDecisionRequested = []string{"courses:read", "profile:read", "tasks:read"}

func mcpScopeDecisionClaims(now time.Time, proof string, allowed []string) map[string]any {
	digest := sha256.Sum256([]byte(proof))
	return map[string]any{
		"iss":              domain.MCPStudentScopeDecisionIssuer,
		"aud":              domain.MCPStudentScopeDecisionAudience,
		"sub":              mcpDecisionTestStudent,
		"typ":              domain.MCPStudentScopeDecisionType,
		"purpose":          domain.MCPStudentScopeDecisionPurpose,
		"requested_scopes": append([]string(nil), mcpScopeDecisionRequested...),
		"allowed_scopes":   allowed,
		"jti":              mcpDecisionTestReply,
		"request_jti":      mcpDecisionTestRequest,
		"request_digest":   fmt.Sprintf("%x", digest[:]),
		"iat":              now.Unix(),
		"exp":              now.Unix() + 15,
	}
}

func mcpScopeDecisionClientForTest(t *testing.T, pem string, now time.Time, requester *mcpStudentRoleReplyRequester) *mcpStudentScopeClient {
	t.Helper()
	verifier, err := newMCPStudentScopeDecisionVerifier(pem)
	if err != nil || verifier == nil {
		t.Fatalf("scopes verifier: %v %v", verifier, err)
	}
	verifier.now = func() time.Time { return now }
	return &mcpStudentScopeClient{conn: requester, decisionVerifier: verifier}
}

func TestMCPStudentScopeClientAcceptsOnlyExplicitSignedSubsets(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	for name, allowed := range map[string][]string{
		"full":    {"courses:read", "profile:read", "tasks:read"},
		"partial": {"courses:read", "tasks:read"},
		"none":    {},
	} {
		t.Run(name, func(t *testing.T) {
			jwt := signReviewerDecisionForTest(t, key, mcpScopeDecisionClaims(now, mcpScopeDecisionTestProof, allowed))
			requester := &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + jwt + `"}`)}
			client := mcpScopeDecisionClientForTest(t, publicPEM, now, requester)
			got, err := client.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
			if err != nil || !reflect.DeepEqual(got, allowed) {
				t.Fatalf("signed scopes got=%v want=%v err=%v", got, allowed, err)
			}
			if got == nil {
				t.Fatal("signed empty result must be an evaluated non-nil slice")
			}
			if requester.subject != mcpStudentScopeSubject || requester.calls != 1 ||
				string(requester.request) != `{"proof":"synthetic-auth-signed-student-scope-proof"}` {
				t.Fatalf("sent to wrong RPC or leaked caller-controlled scopes: %+v", requester)
			}
		})
	}
}

func TestMCPStudentScopeDecisionRejectsSignedWrongClaimsScopesAndBinding(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	otherKey, _ := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	allowed := []string{"courses:read", "tasks:read"}
	mutators := map[string]func(map[string]any){
		"wrong issuer":                func(m map[string]any) { m["iss"] = "auth-service" },
		"wrong audience":              func(m map[string]any) { m["aud"] = domain.MCPStudentRoleDecisionAudience },
		"role-only type":              func(m map[string]any) { m["typ"] = domain.MCPStudentRoleDecisionType },
		"role-only purpose":           func(m map[string]any) { m["purpose"] = domain.MCPStudentRoleDecisionPurpose },
		"wrong subject":               func(m map[string]any) { m["sub"] = "00000000-0000-4000-8000-000000000924" },
		"uppercase subject":           func(m map[string]any) { m["sub"] = strings.ToUpper(mcpDecisionTestStudent) },
		"zero response JTI":           func(m map[string]any) { m["jti"] = "00000000-0000-0000-0000-000000000000" },
		"wrong request JTI":           func(m map[string]any) { m["request_jti"] = "00000000-0000-4000-8000-000000000924" },
		"wrong digest":                func(m map[string]any) { m["request_digest"] = strings.Repeat("0", 64) },
		"uppercase digest":            func(m map[string]any) { m["request_digest"] = strings.ToUpper(m["request_digest"].(string)) },
		"missing request scopes":      func(m map[string]any) { delete(m, "requested_scopes") },
		"null requested scopes":       func(m map[string]any) { m["requested_scopes"] = nil },
		"wrong requested scopes":      func(m map[string]any) { m["requested_scopes"] = []string{"courses:read", "tasks:read"} },
		"reordered requested scopes":  func(m map[string]any) { m["requested_scopes"] = []string{"profile:read", "courses:read", "tasks:read"} },
		"duplicated requested scope":  func(m map[string]any) { m["requested_scopes"] = []string{"courses:read", "courses:read"} },
		"write requested":             func(m map[string]any) { m["requested_scopes"] = []string{"tasks:write"} },
		"null allowed":                func(m map[string]any) { m["allowed_scopes"] = nil },
		"missing allowed":             func(m map[string]any) { delete(m, "allowed_scopes") },
		"unsorted allowed":            func(m map[string]any) { m["allowed_scopes"] = []string{"tasks:read", "courses:read"} },
		"duplicate allowed":           func(m map[string]any) { m["allowed_scopes"] = []string{"courses:read", "courses:read"} },
		"unrequested allowed":         func(m map[string]any) { m["allowed_scopes"] = []string{"lessons:read"} },
		"write allowed":               func(m map[string]any) { m["allowed_scopes"] = []string{"tasks:write"} },
		"wrong allowed type":          func(m map[string]any) { m["allowed_scopes"] = "courses:read" },
		"role assertion substitution": func(m map[string]any) { m["role"] = "student" },
		"future issued":               func(m map[string]any) { m["iat"] = now.Unix() + domain.MCPStudentScopeDecisionFutureSkewSecs + 1 },
		"expired":                     func(m map[string]any) { m["exp"] = now.Unix() },
		"overlong TTL":                func(m map[string]any) { m["exp"] = now.Unix() + domain.MCPStudentScopeDecisionMaxAgeSeconds + 1 },
		"wrong integer type":          func(m map[string]any) { m["iat"] = "1" },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			claims := mcpScopeDecisionClaims(now, mcpScopeDecisionTestProof, allowed)
			mutate(claims)
			jwt := signReviewerDecisionForTest(t, key, claims)
			assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
		})
	}
	t.Run("wrong signing key", func(t *testing.T) {
		jwt := signReviewerDecisionForTest(t, otherKey, mcpScopeDecisionClaims(now, mcpScopeDecisionTestProof, allowed))
		assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
	})
	t.Run("role-only signed ALLOW", func(t *testing.T) {
		jwt := signReviewerDecisionForTest(t, key, mcpDecisionTestClaims(now, mcpScopeDecisionTestProof, "ALLOW"))
		assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
	})
	t.Run("reviewer signed ALLOW", func(t *testing.T) {
		jwt := signReviewerDecisionForTest(t, key, reviewerDecisionTestClaims(now, mcpScopeDecisionTestProof, "ALLOW"))
		assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
	})
	t.Run("wrong incoming proof binding", func(t *testing.T) {
		jwt := signReviewerDecisionForTest(t, key, mcpScopeDecisionClaims(now, mcpScopeDecisionTestProof, allowed))
		assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof+"-changed", mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
		assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof, "00000000-0000-4000-8000-000000000924", mcpDecisionTestRequest, mcpScopeDecisionRequested)
		assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof, mcpDecisionTestStudent, "00000000-0000-4000-8000-000000000924", mcpScopeDecisionRequested)
		assertMCPStudentScopeDenied(t, publicPEM, now, jwt, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, []string{"courses:read"})
	})
}

func TestMCPStudentScopeDecisionRejectsMalformedTokensAndReplies(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	jwt := signReviewerDecisionForTest(t, key, mcpScopeDecisionClaims(now, mcpScopeDecisionTestProof, []string{}))
	for _, invalid := range []string{
		`{"ok":true}`, `{"decision_jwt":null}`, `{"decision_jwt":false}`,
		`{"decision_jwt":""}`, `{"decision_jwt":"` + jwt + `","error":"none"}`,
		`{"decision_jwt":"` + jwt + `","decision_jwt":"` + jwt + `"}`,
		`{"decision_jwt":"` + jwt + `"} trailing`, `[]`,
	} {
		t.Run(invalid[:min(len(invalid), 28)], func(t *testing.T) {
			requester := &mcpStudentRoleReplyRequester{reply: []byte(invalid)}
			client := mcpScopeDecisionClientForTest(t, publicPEM, now, requester)
			if got, err := client.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || got != nil {
				t.Fatalf("malformed reply granted scopes %v, %v", got, err)
			}
		})
	}
	claimsJSON, err := json.Marshal(mcpScopeDecisionClaims(now, mcpScopeDecisionTestProof, []string{}))
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string]string{
		"extra JWT claim":     strings.TrimSuffix(string(claimsJSON), "}") + `,"role":"student"}`,
		"duplicate JWT claim": strings.TrimSuffix(string(claimsJSON), "}") + `,"allowed_scopes":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			token := signMCPStudentDecisionRawJWTForTest(t, key, `{"alg":"RS256","typ":"JWT"}`, payload)
			assertMCPStudentScopeDenied(t, publicPEM, now, token, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
		})
	}
	headerExtra := signMCPStudentDecisionRawJWTForTest(t, key, `{"alg":"RS256","typ":"JWT","kid":"anything"}`, string(claimsJSON))
	assertMCPStudentScopeDenied(t, publicPEM, now, headerExtra, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
	for _, invalid := range []string{"", "invalid", jwt + ".fourth", "eyJhbGciOiJub25lIn0.e30."} {
		assertMCPStudentScopeDenied(t, publicPEM, now, invalid, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested)
	}
}

func TestMCPStudentScopeClientFailsClosedOnReplayOutageAndBadInput(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	jwt := signReviewerDecisionForTest(t, key, mcpScopeDecisionClaims(now, mcpScopeDecisionTestProof, []string{}))
	requester := &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + jwt + `"}`)}
	client := mcpScopeDecisionClientForTest(t, publicPEM, now, requester)
	if got, err := client.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("first signed empty subset incorrectly accepted/denied: %v %v", got, err)
	}
	if got, err := client.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || got != nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replayed response accepted: %v %v", got, err)
	}
	if verifier, err := newMCPStudentScopeDecisionVerifier(""); verifier != nil || err != nil {
		t.Fatalf("missing key must disable verification: %v, %v", verifier, err)
	}
	if verifier, err := newMCPStudentScopeDecisionVerifier("not-public-key"); verifier != nil || err == nil {
		t.Fatalf("invalid key accepted: %v, %v", verifier, err)
	}
	if result, err := NewMCPStudentScopeClient(nil, publicPEM).CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || result != nil {
		t.Fatalf("nil NATS connection accepted: %v, %v", result, err)
	}
	for name, candidate := range map[string]*mcpStudentScopeClient{
		"no verifier":  {conn: requester},
		"no requester": {decisionVerifier: client.decisionVerifier},
		"bad verifier": {conn: requester, decisionVerifierErr: errors.New("bad key")},
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := candidate.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || result != nil {
				t.Fatalf("accepted missing dependency: %v, %v", result, err)
			}
		})
	}
	for _, proof := range []string{"", strings.Repeat("x", maxMCPStudentScopeProofJWTBytes+1)} {
		if result, err := client.CheckMCPStudentScopes(context.Background(), proof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || result != nil {
			t.Fatalf("bad proof accepted: %v, %v", result, err)
		}
	}
	for _, scopes := range [][]string{nil, {}, {"tasks:read", "courses:read"}, {"tasks:write"}} {
		if result, err := client.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, scopes); err == nil || result != nil {
			t.Fatalf("bad requested scopes accepted: %v, %v", result, err)
		}
	}
	for _, identity := range []string{"wrong", "00000000-0000-0000-0000-000000000000"} {
		if result, err := client.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, identity, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || result != nil {
			t.Fatalf("bad identity accepted: %v, %v", result, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := client.CheckMCPStudentScopes(ctx, mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || result != nil {
		t.Fatalf("canceled request accepted: %v, %v", result, err)
	}
	requester.requestErr = errors.New("sensitive signed proof leaked through transport")
	if result, err := client.CheckMCPStudentScopes(context.Background(), mcpScopeDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest, mcpScopeDecisionRequested); err == nil || result != nil || strings.Contains(err.Error(), "sensitive signed proof") {
		t.Fatalf("transport outage leaked data or granted scopes: %v, %v", result, err)
	}
}

func assertMCPStudentScopeDenied(t *testing.T, publicPEM string, now time.Time, token, proof, student, requestJTI string, requested []string) {
	t.Helper()
	requester := &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + token + `"}`)}
	client := mcpScopeDecisionClientForTest(t, publicPEM, now, requester)
	if granted, err := client.CheckMCPStudentScopes(context.Background(), proof, student, requestJTI, requested); err == nil || granted != nil {
		t.Fatalf("invalid signed scopes reply granted %v, err=%v", granted, err)
	}
}
