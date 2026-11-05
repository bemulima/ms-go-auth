package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type reviewerPermissionFixture struct {
	allowed    bool
	err        error
	proof      string
	subject    string
	requestJTI string
}

func (f *reviewerPermissionFixture) HasPermission(_ context.Context, proof, subject, requestJTI string) (bool, error) {
	f.proof = proof
	f.subject = subject
	f.requestJTI = requestJTI
	return f.allowed, f.err
}

func reviewerKeyPEMs(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
	return key, privatePEM, publicPEM
}

func TestKnowledgeReviewerTokenIssuerRequiresExactRBACPermission(t *testing.T) {
	key, privatePEM, publicPEM := reviewerKeyPEMs(t)
	actor := "11111111-1111-4111-8111-111111111111"
	rbac := &reviewerPermissionFixture{allowed: true}
	issuer, err := NewKnowledgeReviewerTokenIssuer("https://auth.synthetic.invalid", privatePEM, publicPEM, rbac)
	if err != nil {
		t.Fatal(err)
	}
	issuer.clock = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	const binding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tokenString, err := issuer.Issue(context.Background(), actor, "APPROVE", binding)
	if err != nil {
		t.Fatal(err)
	}
	proofClaims := jwt.MapClaims{}
	proof, err := jwt.ParseWithClaims(rbac.proof, proofClaims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 || token.Header["typ"] != "JWT" || len(token.Header) != 2 {
			t.Fatalf("unexpected proof JWT header: %#v", token.Header)
		}
		return &key.PublicKey, nil
	}, jwt.WithIssuer("https://auth.synthetic.invalid"), jwt.WithAudience(knowledgePermissionProofAudience), jwt.WithTimeFunc(issuer.clock))
	if err != nil || proof == nil || !proof.Valid {
		t.Fatalf("RBAC proof invalid: %v", err)
	}
	if proofClaims["sub"] != actor || proofClaims["typ"] != knowledgePermissionProofType ||
		proofClaims["purpose"] != knowledgePermissionProofPurpose || proofClaims["permission"] != knowledgeReviewerPerm {
		t.Fatalf("wrong RBAC proof claims: %#v", proofClaims)
	}
	if got := len(proofClaims); got != 9 {
		t.Fatalf("RBAC proof claim count = %d, want exact 9 claims: %#v", got, proofClaims)
	}
	proofJTI, _ := proofClaims["jti"].(string)
	if !canonicalReviewerUUID(proofJTI) {
		t.Fatalf("proof jti is not a canonical UUID: %q", proofJTI)
	}
	if rbac.subject != actor || rbac.requestJTI != proofJTI {
		t.Fatalf("permission request binding = (%q, %q), want (%q, %q)", rbac.subject, rbac.requestJTI, actor, proofJTI)
	}
	proofIAT, iatOK := proofClaims["iat"].(float64)
	proofEXP, expOK := proofClaims["exp"].(float64)
	if !iatOK || !expOK || proofEXP-proofIAT != knowledgePermissionProofTTL.Seconds() {
		t.Fatalf("unexpected proof lifetime claims: %#v", proofClaims)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 || token.Header["typ"] != "JWT" {
			t.Fatalf("unexpected JWT header: %#v", token.Header)
		}
		return &key.PublicKey, nil
	}, jwt.WithIssuer("https://auth.synthetic.invalid"), jwt.WithAudience(knowledgeReviewerAudience), jwt.WithTimeFunc(issuer.clock))
	if err != nil || token == nil || !token.Valid {
		t.Fatalf("signed reviewer token invalid: %v", err)
	}
	if claims["permission"] != knowledgeReviewerPerm || claims["decision"] != "APPROVE" || claims["review_binding_digest"] != binding || claims["sub"] != actor || claims["typ"] != knowledgeReviewerType {
		t.Fatalf("wrong reviewer claims: %#v", claims)
	}
	reviewerJTI, ok := claims["jti"].(string)
	if !ok || !canonicalReviewerUUID(reviewerJTI) || reviewerJTI == proofJTI {
		t.Fatalf("reviewer jti is missing, malformed, or reused from the RBAC proof: %q", reviewerJTI)
	}
	if exp, ok := claims["exp"].(float64); !ok || exp-float64(issuer.clock().Unix()) > knowledgeReviewerTokenTTL.Seconds() {
		t.Fatalf("reviewer token TTL too long: %#v", claims["exp"])
	}
	secondTokenString, err := issuer.Issue(context.Background(), actor, "REJECT", binding)
	if err != nil {
		t.Fatal(err)
	}
	secondClaims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(secondTokenString, secondClaims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithTimeFunc(issuer.clock)); err != nil {
		t.Fatal(err)
	}
	secondReviewerJTI, _ := secondClaims["jti"].(string)
	if secondClaims["decision"] != "REJECT" {
		t.Fatalf("REJECT decision claim = %#v", secondClaims["decision"])
	}
	secondProofClaims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(rbac.proof, secondProofClaims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithTimeFunc(issuer.clock)); err != nil {
		t.Fatal(err)
	}
	secondProofJTI, _ := secondProofClaims["jti"].(string)
	if secondReviewerJTI == reviewerJTI || secondProofJTI == proofJTI || secondReviewerJTI == secondProofJTI {
		t.Fatalf("reviewer issuance reused a jti: first=(%q,%q) second=(%q,%q)", reviewerJTI, proofJTI, secondReviewerJTI, secondProofJTI)
	}
	revisionToken, err := issuer.IssueV2(context.Background(), actor, "NEEDS_REVISION", binding)
	if err != nil {
		t.Fatal(err)
	}
	revisionClaims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(revisionToken, revisionClaims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithTimeFunc(issuer.clock)); err != nil {
		t.Fatal(err)
	}
	if revisionClaims["decision"] != "NEEDS_REVISION" || revisionClaims["review_binding_digest"] != binding || revisionClaims["sub"] != actor {
		t.Fatal("revision review lost binding")
	}

}

func TestKnowledgeReviewerTokenIssuerFailsClosedForRBACAndMalformedInput(t *testing.T) {
	_, privatePEM, publicPEM := reviewerKeyPEMs(t)
	actor := "11111111-1111-4111-8111-111111111111"
	binding := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for name, fixture := range map[string]struct {
		fixture *reviewerPermissionFixture
		want    error
	}{
		"permission denied":     {&reviewerPermissionFixture{allowed: false}, ErrKnowledgeReviewerDenied},
		"authority unavailable": {&reviewerPermissionFixture{err: errors.New("offline")}, ErrKnowledgeReviewerUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			issuer, err := NewKnowledgeReviewerTokenIssuer("https://auth.synthetic.invalid", privatePEM, publicPEM, fixture.fixture)
			if err != nil {
				t.Fatal(err)
			}
			if token, err := issuer.Issue(context.Background(), actor, "APPROVE", binding); token != "" || !errors.Is(err, fixture.want) {
				t.Fatalf("Issue() = (%q, %v), want empty token and %v", token, err, fixture.want)
			}
		})
	}
	issuer, err := NewKnowledgeReviewerTokenIssuer("https://auth.synthetic.invalid", privatePEM, publicPEM, &reviewerPermissionFixture{allowed: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ actor, decision, digest string }{
		{"not-uuid", "APPROVE", binding}, {actor, "PUBLISH", binding}, {actor, "NEEDS_REVISION", binding}, {actor, "APPROVE", "ABC"},
		{"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "APPROVE", binding},
	} {
		if token, err := issuer.Issue(context.Background(), input.actor, input.decision, input.digest); token != "" || !errors.Is(err, ErrKnowledgeReviewerUnavailable) {
			t.Fatalf("malformed Issue(%#v) = (%q, %v)", input, token, err)
		}
	}
	if rbac := issuer.rbac.(*reviewerPermissionFixture); rbac.proof != "" {
		t.Fatalf("malformed actor reached RBAC lookup: %#v", rbac)
	}
}

func TestKnowledgeReviewerTokenIssuerDisabledWithoutKeyOrPermissionPort(t *testing.T) {
	if issuer, err := NewKnowledgeReviewerTokenIssuer("https://auth.synthetic.invalid", "", "", &reviewerPermissionFixture{}); err != nil || issuer != nil {
		t.Fatalf("empty key must keep issuer disabled: (%v, %v)", issuer, err)
	}
	if _, err := NewKnowledgeReviewerTokenIssuer("https://auth.synthetic.invalid", "", "", nil); !errors.Is(err, ErrKnowledgeReviewerUnavailable) {
		t.Fatalf("missing permission port error = %v", err)
	}
}

func TestKnowledgeReviewerTokenIssuerRejectsUnmatchedOrWeakRSAKeys(t *testing.T) {
	_, privatePEM, _ := reviewerKeyPEMs(t)
	_, _, otherPublicPEM := reviewerKeyPEMs(t)
	if issuer, err := NewKnowledgeReviewerTokenIssuer("https://auth.synthetic.invalid", privatePEM, otherPublicPEM, &reviewerPermissionFixture{}); issuer != nil || !errors.Is(err, ErrKnowledgeReviewerUnavailable) {
		t.Fatalf("mismatched RSA pair = (%v, %v), want unavailable", issuer, err)
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPrivatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weakKey)}))
	weakPublicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&weakKey.PublicKey)}))
	if issuer, err := NewKnowledgeReviewerTokenIssuer("https://auth.synthetic.invalid", weakPrivatePEM, weakPublicPEM, &reviewerPermissionFixture{}); issuer != nil || !errors.Is(err, ErrKnowledgeReviewerUnavailable) {
		t.Fatalf("weak RSA pair = (%v, %v), want unavailable", issuer, err)
	}
}
