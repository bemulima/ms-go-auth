package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

const mcpStudentRoleTestSubject = "11111111-1111-4111-8111-111111111111"

func TestMCPStudentRoleProofSignsOnlyFixedStudentRoleLookup(t *testing.T) {
	key, privatePEM, publicPEM := reviewerKeyPEMs(t)
	signer, err := NewMCPStudentRoleProofSigner("auth-service", privatePEM, publicPEM)
	if err != nil || signer == nil {
		t.Fatalf("MCP role signer: (%v, %v)", signer, err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	signer.clock = func() time.Time { return now }
	proof, requestJTI, err := signer.Sign(context.Background(), mcpStudentRoleTestSubject)
	if err != nil || proof == "" || !canonicalReviewerUUID(requestJTI) {
		t.Fatalf("MCP proof: JTI=%q error=%v", requestJTI, err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("MCP proof has %d parts", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil || len(header) != 2 || header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("MCP proof header: %#v, %v", header, err)
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(proof, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			t.Fatalf("unexpected signing method: %v", token.Method)
		}
		return &key.PublicKey, nil
	}, jwt.WithIssuer("auth-service"), jwt.WithAudience(domain.MCPStudentRoleProofAudience), jwt.WithTimeFunc(signer.clock))
	if err != nil || parsed == nil || !parsed.Valid {
		t.Fatalf("signed MCP proof fails JWT validation: %v", err)
	}
	if len(claims) != 9 || claims["iss"] != "auth-service" || claims["sub"] != mcpStudentRoleTestSubject ||
		claims["typ"] != domain.MCPStudentRoleProofType || claims["purpose"] != domain.MCPStudentRoleProofPurpose ||
		claims["role"] != domain.MCPStudentRole || claims["jti"] != requestJTI {
		t.Fatalf("MCP proof claims do not match exact role-only contract: %#v", claims)
	}
	iat, issued := claims["iat"].(float64)
	exp, expires := claims["exp"].(float64)
	if !issued || !expires || exp-iat != domain.MCPStudentRoleProofTTLSeconds || iat != float64(now.Unix()) {
		t.Fatalf("MCP proof time claims: %#v", claims)
	}
	secondProof, secondJTI, err := signer.Sign(context.Background(), mcpStudentRoleTestSubject)
	if err != nil || secondJTI == requestJTI || secondProof == proof {
		t.Fatalf("MCP proof JTI was reused: %v", err)
	}
}

func TestMCPStudentRoleProofDisabledOrInvalidKeysAndIdentityFailClosed(t *testing.T) {
	_, privatePEM, publicPEM := reviewerKeyPEMs(t)
	if signer, err := NewMCPStudentRoleProofSigner("auth-service", "", ""); signer != nil || err != nil {
		t.Fatalf("missing keys must disable signer: (%v, %v)", signer, err)
	}
	for _, config := range []struct{ issuer, private, public string }{
		{"", privatePEM, publicPEM},
		{"auth-service", privatePEM, ""},
		{"auth-service", "", publicPEM},
		{"auth-service", "invalid-key", publicPEM},
	} {
		if signer, err := NewMCPStudentRoleProofSigner(config.issuer, config.private, config.public); signer != nil || !errors.Is(err, ErrMCPStudentRoleProofUnavailable) {
			t.Fatalf("accepted invalid key configuration: (%v, %v)", signer, err)
		}
	}
	_, _, unrelatedPublicPEM := reviewerKeyPEMs(t)
	if signer, err := NewMCPStudentRoleProofSigner("auth-service", privatePEM, unrelatedPublicPEM); signer != nil || !errors.Is(err, ErrMCPStudentRoleProofUnavailable) {
		t.Fatalf("accepted mismatched RSA key pair: (%v, %v)", signer, err)
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPrivate := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weakKey)}))
	weakPublic := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&weakKey.PublicKey)}))
	if signer, err := NewMCPStudentRoleProofSigner("auth-service", weakPrivate, weakPublic); signer != nil || !errors.Is(err, ErrMCPStudentRoleProofUnavailable) {
		t.Fatalf("accepted weak RSA key pair: (%v, %v)", signer, err)
	}
	signer, err := NewMCPStudentRoleProofSigner("auth-service", privatePEM, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		context context.Context
		subject string
	}{
		{context.Background(), "invalid"},
		{context.Background(), "11111111-1111-4111-8111-11111111111A"},
		{context.Background(), "00000000-0000-0000-0000-000000000000"},
		{nil, mcpStudentRoleTestSubject},
		{ctx, mcpStudentRoleTestSubject},
	} {
		if proof, jti, err := signer.Sign(input.context, input.subject); proof != "" || jti != "" || !errors.Is(err, ErrMCPStudentRoleProofUnavailable) {
			t.Fatalf("accepted invalid signer input: proof=%q JTI=%q error=%v", proof, jti, err)
		}
	}
	var disabled *MCPStudentRoleProofSigner
	if proof, jti, err := disabled.Sign(context.Background(), mcpStudentRoleTestSubject); proof != "" || jti != "" || !errors.Is(err, ErrMCPStudentRoleProofUnavailable) {
		t.Fatalf("nil signer issued proof: %q %q %v", proof, jti, err)
	}
}
