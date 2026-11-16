package natsadapter

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	nats "github.com/nats-io/nats.go"
)

const (
	mcpDecisionTestStudent = "00000000-0000-4000-8000-0000000009a1"
	mcpDecisionTestRequest = "00000000-0000-4000-8000-000000000922"
	mcpDecisionTestReply   = "00000000-0000-4000-8000-000000000923"
	mcpDecisionTestProof   = "synthetic-auth-signed-student-role-proof"
)

type mcpStudentRoleReplyRequester struct {
	reply       []byte
	request    []byte
	subject    string
	calls      int
	requestErr error
}

func (requester *mcpStudentRoleReplyRequester) RequestWithContext(_ context.Context, subject string, payload []byte) (*nats.Msg, error) {
	requester.calls++
	requester.subject = subject
	requester.request = append([]byte(nil), payload...)
	if requester.requestErr != nil {
		return nil, requester.requestErr
	}
	return &nats.Msg{Data: append([]byte(nil), requester.reply...)}, nil
}

func mcpDecisionTestClaims(now time.Time, proof, decision string) map[string]any {
	digest := sha256.Sum256([]byte(proof))
	return map[string]any{
		"iss": domain.MCPStudentRoleDecisionIssuer, "aud": domain.MCPStudentRoleDecisionAudience,
		"sub": mcpDecisionTestStudent, "typ": domain.MCPStudentRoleDecisionType,
		"purpose": domain.MCPStudentRoleDecisionPurpose, "role": domain.MCPStudentRole,
		"decision": decision, "jti": mcpDecisionTestReply, "request_jti": mcpDecisionTestRequest,
		"request_digest": fmt.Sprintf("%x", digest[:]), "iat": now.Unix(), "exp": now.Unix() + 15,
	}
}

func mcpStudentRoleClientForTest(t *testing.T, publicPEM string, now time.Time, requester *mcpStudentRoleReplyRequester) *mcpStudentRoleClient {
	t.Helper()
	verifier, err := newMCPStudentRoleDecisionVerifier(publicPEM)
	if err != nil || verifier == nil {
		t.Fatalf("MCP role decision verifier: (%v, %v)", verifier, err)
	}
	verifier.now = func() time.Time { return now }
	return &mcpStudentRoleClient{conn: requester, decisionVerifier: verifier}
}

func TestMCPStudentRoleClientAcceptsOnlySignedFreshAndBoundAllowOrDeny(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, decision := range []string{"ALLOW", "DENY"} {
		t.Run(decision, func(t *testing.T) {
			token := signReviewerDecisionForTest(t, key, mcpDecisionTestClaims(now, mcpDecisionTestProof, decision))
			requester := &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + token + `"}`)}
			client := mcpStudentRoleClientForTest(t, publicPEM, now, requester)
			allowed, err := client.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest)
			if err != nil || allowed != (decision == "ALLOW") {
				t.Fatalf("signed role %s returned allowed=%v err=%v", decision, allowed, err)
			}
			if requester.subject != mcpStudentRoleSubject || requester.calls != 1 || string(requester.request) != `{"proof":"synthetic-auth-signed-student-role-proof"}` {
				t.Fatalf("MCP request left its dedicated signed subject/shape: %+v", requester)
			}
		})
	}
}

func TestMCPStudentRoleClientRejectsWrongSignedDecisionBindingsAndAuthority(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	otherKey, _ := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	mutators := map[string]func(map[string]any){
		"wrong issuer":             func(m map[string]any) { m["iss"] = "auth-service" },
		"wrong audience":           func(m map[string]any) { m["aud"] = "ms-go-auth-knowledge-review-permission-decision" },
		"wrong type":               func(m map[string]any) { m["typ"] = "knowledge_graph_permission_decision" },
		"wrong purpose":            func(m map[string]any) { m["purpose"] = "RBAC_AUTH_KNOWLEDGE_GRAPH_REVIEW_DECISION_V1" },
		"wrong role":               func(m map[string]any) { m["role"] = "admin" },
		"wrong decision":           func(m map[string]any) { m["decision"] = "ALLOW_ALL" },
		"wrong subject":            func(m map[string]any) { m["sub"] = "00000000-0000-4000-8000-000000000924" },
		"noncanonical subject":     func(m map[string]any) { m["sub"] = strings.ToUpper(mcpDecisionTestStudent) },
		"zero response JTI":       func(m map[string]any) { m["jti"] = "00000000-0000-0000-0000-000000000000" },
		"bad request JTI":         func(m map[string]any) { m["request_jti"] = "00000000-0000-4000-8000-000000000924" },
		"bad request digest":      func(m map[string]any) { m["request_digest"] = strings.Repeat("0", 64) },
		"uppercase digest":        func(m map[string]any) { m["request_digest"] = strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256([]byte(mcpDecisionTestProof)))) },
		"expired decision":        func(m map[string]any) { m["exp"] = now.Unix() },
		"future issued":           func(m map[string]any) { m["iat"] = now.Unix() + domain.MCPStudentRoleDecisionFutureSkewSecs + 1 },
		"overlong lifetime":       func(m map[string]any) { m["exp"] = now.Unix() + domain.MCPStudentRoleDecisionMaxAgeSeconds + 1 },
		"invalid time type":       func(m map[string]any) { m["iat"] = "now" },
		"additional scope":        func(m map[string]any) { m["scope"] = "tasks:write" },
		"missing role":            func(m map[string]any) { delete(m, "role") },
		"null decision":           func(m map[string]any) { m["decision"] = nil },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			claims := mcpDecisionTestClaims(now, mcpDecisionTestProof, "ALLOW")
			mutate(claims)
			token := signReviewerDecisionForTest(t, key, claims)
			assertMCPStudentRoleDecisionDenied(t, publicPEM, now, token, mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest)
		})
	}
	t.Run("wrong key", func(t *testing.T) {
		token := signReviewerDecisionForTest(t, otherKey, mcpDecisionTestClaims(now, mcpDecisionTestProof, "ALLOW"))
		assertMCPStudentRoleDecisionDenied(t, publicPEM, now, token, mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest)
	})
	t.Run("reviewer decision cannot grant MCP role", func(t *testing.T) {
		claims := reviewerDecisionTestClaims(now, mcpDecisionTestProof, "ALLOW")
		token := signReviewerDecisionForTest(t, key, claims)
		assertMCPStudentRoleDecisionDenied(t, publicPEM, now, token, mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest)
	})
	t.Run("request binding changed", func(t *testing.T) {
		token := signReviewerDecisionForTest(t, key, mcpDecisionTestClaims(now, mcpDecisionTestProof, "ALLOW"))
		assertMCPStudentRoleDecisionDenied(t, publicPEM, now, token, mcpDecisionTestProof+"-different", mcpDecisionTestStudent, mcpDecisionTestRequest)
		assertMCPStudentRoleDecisionDenied(t, publicPEM, now, token, mcpDecisionTestProof, mcpDecisionTestStudent, "00000000-0000-4000-8000-000000000924")
		assertMCPStudentRoleDecisionDenied(t, publicPEM, now, token, mcpDecisionTestProof, "00000000-0000-4000-8000-000000000924", mcpDecisionTestRequest)
	})
}

func TestMCPStudentRoleDecisionRejectsMalformedJWTAndResponseJSON(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	token := signReviewerDecisionForTest(t, key, mcpDecisionTestClaims(now, mcpDecisionTestProof, "ALLOW"))
	invalidReplies := []string{
		`{"ok":true}`, `{"decision_jwt":null}`, `{"decision_jwt":false}`,
		`{"decision_jwt":"` + token + `","ok":true}`,
		`{"decision_jwt":"` + token + `","decision_jwt":"` + token + `"}`,
		`{"decision_jwt":"` + token + `"} true`, `[]`, `{"decision_jwt":""}`,
	}
	for _, reply := range invalidReplies {
		t.Run(reply[:min(len(reply), 32)], func(t *testing.T) {
			requester := &mcpStudentRoleReplyRequester{reply: []byte(reply)}
			client := mcpStudentRoleClientForTest(t, publicPEM, now, requester)
			if allowed, err := client.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed {
				t.Fatalf("accepted malformed MCP reply: allowed=%v err=%v", allowed, err)
			}
		})
	}
	claimsBytes, err := json.Marshal(mcpDecisionTestClaims(now, mcpDecisionTestProof, "ALLOW"))
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string]string{
		"extra signed JWT claim":   strings.TrimSuffix(string(claimsBytes), "}") + `,"scope":"tasks:write"}`,
		"duplicate signed JWT claim": strings.TrimSuffix(string(claimsBytes), "}") + `,"role":"student"}`,
	} {
		t.Run(name, func(t *testing.T) {
			invalidToken := signMCPStudentDecisionRawJWTForTest(t, key, `{"alg":"RS256","typ":"JWT"}`, payload)
			assertMCPStudentRoleDecisionDenied(t, publicPEM, now, invalidToken, mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest)
		})
	}
	invalidHeaderToken := signMCPStudentDecisionRawJWTForTest(t, key, `{"alg":"RS256","typ":"JWT","kid":"any"}`, string(claimsBytes))
	assertMCPStudentRoleDecisionDenied(t, publicPEM, now, invalidHeaderToken, mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest)
	for _, invalidToken := range []string{"invalid", token + ".unexpected", "", "eyJhbGciOiJub25lIn0.e30."} {
		assertMCPStudentRoleDecisionDenied(t, publicPEM, now, invalidToken, mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest)
	}
}

func TestMCPStudentRoleClientRejectsReplayMissingKeysOversizeAndOutage(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	token := signReviewerDecisionForTest(t, key, mcpDecisionTestClaims(now, mcpDecisionTestProof, "ALLOW"))
	requester := &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + token + `"}`)}
	client := mcpStudentRoleClientForTest(t, publicPEM, now, requester)
	if allowed, err := client.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest); err != nil || !allowed {
		t.Fatalf("first bound decision rejected: %v, %v", allowed, err)
	}
	if allowed, err := client.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replayed signed decision accepted: %v, %v", allowed, err)
	}
	if verifier, err := newMCPStudentRoleDecisionVerifier(""); verifier != nil || err != nil {
		t.Fatalf("absent RBAC public key must keep verifier disabled: (%v, %v)", verifier, err)
	}
	if verifier, err := newMCPStudentRoleDecisionVerifier("invalid public key"); verifier != nil || err == nil {
		t.Fatalf("invalid RBAC public key accepted: (%v, %v)", verifier, err)
	}
	// A typed-nil NATS connection must not turn into a non-nil transport port.
	publicClient := NewMCPStudentRoleClient(nil, publicPEM)
	if allowed, err := publicClient.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed {
		t.Fatalf("nil NATS connection accepted: %v, %v", allowed, err)
	}
	for name, candidate := range map[string]*mcpStudentRoleClient{
		"no configured verifier": {conn: requester},
		"no requester":           {decisionVerifier: client.decisionVerifier},
		"invalid verifier config": {conn: requester, decisionVerifierErr: errors.New("invalid key")},
	} {
		t.Run(name, func(t *testing.T) {
			if allowed, err := candidate.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed {
				t.Fatalf("missing dependency accepted: %v, %v", allowed, err)
			}
		})
	}
	for _, invalid := range []string{"", strings.Repeat("x", maxMCPStudentRoleRequestBytes)} {
		if allowed, err := client.CheckMCPStudentRole(context.Background(), invalid, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed {
			t.Fatalf("accepted empty/oversized request: %v, %v", allowed, err)
		}
	}
	for _, invalidSubject := range []string{"not-uuid", "00000000-0000-0000-0000-000000000000"} {
		if allowed, err := client.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, invalidSubject, mcpDecisionTestRequest); err == nil || allowed {
			t.Fatalf("accepted invalid subject: %v, %v", allowed, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if allowed, err := client.CheckMCPStudentRole(ctx, mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed {
		t.Fatalf("accepted canceled request: %v, %v", allowed, err)
	}
	requester.requestErr = errors.New("private transport diagnostic with sensitive token")
	client = mcpStudentRoleClientForTest(t, publicPEM, now, requester)
	if allowed, err := client.CheckMCPStudentRole(context.Background(), mcpDecisionTestProof, mcpDecisionTestStudent, mcpDecisionTestRequest); err == nil || allowed || strings.Contains(err.Error(), "private transport diagnostic") || strings.Contains(err.Error(), mcpDecisionTestProof) {
		t.Fatalf("outage leaked or granted authority: %v, %v", allowed, err)
	}
}

func assertMCPStudentRoleDecisionDenied(t *testing.T, publicPEM string, now time.Time, token, proof, studentID, requestJTI string) {
	t.Helper()
	requester := &mcpStudentRoleReplyRequester{reply: []byte(`{"decision_jwt":"` + token + `"}`)}
	client := mcpStudentRoleClientForTest(t, publicPEM, now, requester)
	if allowed, err := client.CheckMCPStudentRole(context.Background(), proof, studentID, requestJTI); err == nil || allowed {
		t.Fatalf("invalid signed MCP role decision accepted: allowed=%v err=%v", allowed, err)
	}
}

func signMCPStudentDecisionRawJWTForTest(t *testing.T, key *rsa.PrivateKey, header, claims string) string {
	t.Helper()
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}
