package natsadapter

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	nats "github.com/nats-io/nats.go"
)

func TestRBACPermissionCheckRequestContainsOnlySignedProof(t *testing.T) {
	got, err := json.Marshal(rbacPermissionCheckRequest{Proof: "synthetic-signed-proof"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"proof":"synthetic-signed-proof"}` {
		t.Fatalf("permission lookup request = %s", got)
	}
}

const (
	reviewerDecisionTestSubject  = "00000000-0000-4000-8000-000000000901"
	reviewerDecisionTestRequest  = "00000000-0000-4000-8000-000000000902"
	reviewerDecisionTestResponse = "00000000-0000-4000-8000-000000000903"
)

type reviewerPermissionReplyRequester struct {
	reply   []byte
	request []byte
	subject string
	calls   int
}

func (requester *reviewerPermissionReplyRequester) RequestWithContext(_ context.Context, subject string, body []byte) (*nats.Msg, error) {
	requester.calls++
	requester.subject = subject
	requester.request = append([]byte(nil), body...)
	return &nats.Msg{Data: append([]byte(nil), requester.reply...)}, nil
}

func TestRBACPermissionClientVerifiesSignedAllowAndDenyResponses(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	proof := "signed-auth-proof"
	for _, decision := range []string{"ALLOW", "DENY"} {
		t.Run(decision, func(t *testing.T) {
			claims := reviewerDecisionTestClaims(now, proof, decision)
			token := signReviewerDecisionForTest(t, key, claims)
			requester := &reviewerPermissionReplyRequester{reply: []byte(`{"decision_jwt":"` + token + `"}`)}
			verifier, err := newReviewerPermissionDecisionVerifier(publicPEM)
			if err != nil {
				t.Fatal(err)
			}
			verifier.now = func() time.Time { return now }
			client := &rbacPermissionClient{conn: requester, subject: "rbac.checkPermission", decisionVerifier: verifier}
			allowed, err := client.HasPermission(context.Background(), proof, reviewerDecisionTestSubject, reviewerDecisionTestRequest)
			if err != nil || allowed != (decision == "ALLOW") {
				t.Fatalf("signed %s = (%v, %v)", decision, allowed, err)
			}
			if requester.subject != "rbac.checkPermission" || string(requester.request) != `{"proof":"signed-auth-proof"}` {
				t.Fatalf("request changed established NATS contract: subject=%q payload=%s", requester.subject, requester.request)
			}
		})
	}
}

func TestRBACPermissionClientRejectsUnsignedInvalidAndMismatchedReplies(t *testing.T) {
	key, publicPEM := reviewerDecisionTestKey(t)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	proof := "signed-auth-proof"
	mutators := map[string]func(map[string]any){
		"issuer":                   func(c map[string]any) { c["iss"] = "untrusted-rbac" },
		"audience":                 func(c map[string]any) { c["aud"] = "other-audience" },
		"type":                     func(c map[string]any) { c["typ"] = "knowledge_graph_reviewer" },
		"purpose":                  func(c map[string]any) { c["purpose"] = "other-purpose" },
		"subject":                  func(c map[string]any) { c["sub"] = "00000000-0000-4000-8000-000000000904" },
		"permission":               func(c map[string]any) { c["permission"] = "knowledge_graph.publish" },
		"decision":                 func(c map[string]any) { c["decision"] = "ALLOW_ALL" },
		"response jti":             func(c map[string]any) { c["jti"] = "00000000-0000-0000-0000-000000000000" },
		"request jti":              func(c map[string]any) { c["request_jti"] = "00000000-0000-4000-8000-000000000904" },
		"request digest":           func(c map[string]any) { c["request_digest"] = strings.Repeat("a", 64) },
		"expired":                  func(c map[string]any) { c["exp"] = now.Unix() },
		"lifetime over 30 seconds": func(c map[string]any) { c["exp"] = now.Unix() + domain.ReviewerPermissionDecisionMaxAgeSeconds + 1 },
		"future issued at":         func(c map[string]any) { c["iat"] = now.Unix() + domain.ReviewerPermissionDecisionFutureSkewSeconds + 1 },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			claims := reviewerDecisionTestClaims(now, proof, "ALLOW")
			mutate(claims)
			assertReviewerDecisionRejected(t, publicPEM, now, proof, signReviewerDecisionForTest(t, key, claims), reviewerDecisionTestSubject, reviewerDecisionTestRequest)
		})
	}
	t.Run("wrong signing key", func(t *testing.T) {
		token := signReviewerDecisionForTest(t, wrongKey, reviewerDecisionTestClaims(now, proof, "ALLOW"))
		assertReviewerDecisionRejected(t, publicPEM, now, proof, token, reviewerDecisionTestSubject, reviewerDecisionTestRequest)
	})
	t.Run("unsigned generic pass", func(t *testing.T) {
		assertReviewerDecisionRejected(t, publicPEM, now, proof, "", reviewerDecisionTestSubject, reviewerDecisionTestRequest)
		requester := &reviewerPermissionReplyRequester{reply: []byte(`{"ok":true}`)}
		verifier, _ := newReviewerPermissionDecisionVerifier(publicPEM)
		verifier.now = func() time.Time { return now }
		client := &rbacPermissionClient{conn: requester, subject: "rbac.checkPermission", decisionVerifier: verifier}
		if allowed, err := client.HasPermission(context.Background(), proof, reviewerDecisionTestSubject, reviewerDecisionTestRequest); err == nil || allowed {
			t.Fatalf("unsigned generic PASS accepted: allowed=%v err=%v", allowed, err)
		}
	})
	t.Run("changed expected subject", func(t *testing.T) {
		token := signReviewerDecisionForTest(t, key, reviewerDecisionTestClaims(now, proof, "ALLOW"))
		assertReviewerDecisionRejected(t, publicPEM, now, proof, token, "00000000-0000-4000-8000-000000000904", reviewerDecisionTestRequest)
	})
	t.Run("reply replay", func(t *testing.T) {
		token := signReviewerDecisionForTest(t, key, reviewerDecisionTestClaims(now, proof, "ALLOW"))
		requester := &reviewerPermissionReplyRequester{reply: []byte(`{"decision_jwt":"` + token + `"}`)}
		verifier, _ := newReviewerPermissionDecisionVerifier(publicPEM)
		verifier.now = func() time.Time { return now }
		client := &rbacPermissionClient{conn: requester, subject: "rbac.checkPermission", decisionVerifier: verifier}
		if allowed, err := client.HasPermission(context.Background(), proof, reviewerDecisionTestSubject, reviewerDecisionTestRequest); err != nil || !allowed {
			t.Fatalf("first reply: allowed=%v err=%v", allowed, err)
		}
		if allowed, err := client.HasPermission(context.Background(), proof, reviewerDecisionTestSubject, reviewerDecisionTestRequest); err == nil || allowed || !strings.Contains(err.Error(), "replayed") {
			t.Fatalf("replayed JTI accepted: allowed=%v err=%v", allowed, err)
		}
	})
	t.Run("old reply for fresh request", func(t *testing.T) {
		token := signReviewerDecisionForTest(t, key, reviewerDecisionTestClaims(now, proof, "ALLOW"))
		assertReviewerDecisionRejected(t, publicPEM, now, proof, token, reviewerDecisionTestSubject, "00000000-0000-4000-8000-000000000904")
	})
	t.Run("missing configured verifier", func(t *testing.T) {
		verifier, err := newReviewerPermissionDecisionVerifier("")
		if err != nil || verifier != nil {
			t.Fatalf("missing key config = (%v, %v)", verifier, err)
		}
		client := &rbacPermissionClient{conn: &reviewerPermissionReplyRequester{}, subject: "rbac.checkPermission", decisionVerifier: verifier}
		if allowed, err := client.HasPermission(context.Background(), proof, reviewerDecisionTestSubject, reviewerDecisionTestRequest); err == nil || allowed {
			t.Fatalf("missing verifier config did not fail closed: allowed=%v err=%v", allowed, err)
		}
	})
}

func assertReviewerDecisionRejected(t *testing.T, publicPEM string, now time.Time, proof, token, subject, requestJTI string) {
	t.Helper()
	verifier, err := newReviewerPermissionDecisionVerifier(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	requester := &reviewerPermissionReplyRequester{reply: []byte(`{"decision_jwt":"` + token + `"}`)}
	client := &rbacPermissionClient{conn: requester, subject: "rbac.checkPermission", decisionVerifier: verifier}
	if allowed, err := client.HasPermission(context.Background(), proof, subject, requestJTI); err == nil || allowed {
		t.Fatalf("invalid decision accepted: allowed=%v err=%v", allowed, err)
	}
}

func reviewerDecisionTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	return key, string(publicPEM)
}

func reviewerDecisionTestClaims(now time.Time, proof, decision string) map[string]any {
	requestDigest := sha256.Sum256([]byte(proof))
	return map[string]any{
		"iss": domain.ReviewerPermissionDecisionIssuer, "aud": domain.ReviewerPermissionDecisionAudience,
		"sub": reviewerDecisionTestSubject, "typ": domain.ReviewerPermissionDecisionType,
		"purpose": domain.ReviewerPermissionDecisionPurpose, "permission": domain.KnowledgeGraphReviewPermission,
		"decision": decision, "jti": reviewerDecisionTestResponse, "request_jti": reviewerDecisionTestRequest,
		"request_digest": fmt.Sprintf("%x", requestDigest[:]), "iat": now.Unix(),
		"exp": now.Unix() + domain.ReviewerPermissionDecisionTTLSeconds,
	}
}

func signReviewerDecisionForTest(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(encodedClaims)
	unsigned := header + "." + payload
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}
