package usecase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

func testMCPStudentScopeSnapshot(now time.Time) *domain.MCPExternalAuthGrantSnapshot {
	return &domain.MCPExternalAuthGrantSnapshot{
		StudentID:        mcpStudentRoleTestSubject,
		ConsentID:        "22222222-2222-4222-8222-222222222222",
		ClientID:         "trusted-mcp-client",
		ResourceURI:      "https://mcp.example.test",
		ConsentExpiresAt: now.Add(time.Hour),
		ClientScopes:     []string{"profile:read", "courses:read", "tasks:read", "lessons:read"},
		ConsentScopes:    []string{"tasks:read", "courses:read", "profile:read"},
	}
}

func TestMCPStudentScopeProofSignsOnlyAuthGrantBoundPilotScopes(t *testing.T) {
	key, privatePEM, publicPEM := reviewerKeyPEMs(t)
	signer, err := NewMCPStudentScopeProofSigner("auth-service", privatePEM, publicPEM)
	if err != nil || signer == nil {
		t.Fatalf("MCP scopes signer: %v, %v", signer, err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	signer.clock = func() time.Time { return now }
	requested := []string{"courses:read", "profile:read", "tasks:read"}
	proof, jti, err := signer.Sign(context.Background(), testMCPStudentScopeSnapshot(now), requested)
	if err != nil || proof == "" || !canonicalReviewerUUID(jti) {
		t.Fatalf("sign scope proof: jti=%q err=%v", jti, err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three JWT parts: %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil || len(header) != 2 || header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("noncanonical JWT header: %#v err=%v", header, err)
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(proof, claims, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithIssuer("auth-service"), jwt.WithAudience(domain.MCPStudentScopeProofAudience), jwt.WithTimeFunc(signer.clock))
	if err != nil || parsed == nil || !parsed.Valid {
		t.Fatalf("invalid proof signature/claims: %v", err)
	}
	if len(claims) != 9 || claims["iss"] != "auth-service" ||
		claims["sub"] != mcpStudentRoleTestSubject || claims["typ"] != domain.MCPStudentScopeProofType ||
		claims["purpose"] != domain.MCPStudentScopeProofPurpose || claims["jti"] != jti {
		t.Fatalf("unexpected scope claim envelope: %#v", claims)
	}
	actual, ok := claims["scopes"].([]any)
	if !ok || len(actual) != len(requested) {
		t.Fatalf("wrong scope claim type: %#v", claims["scopes"])
	}
	for i, scope := range requested {
		if actual[i] != scope {
			t.Fatalf("scopes mismatch: got=%#v want=%v", actual, requested)
		}
	}
	issuedAt, issued := claims["iat"].(float64)
	expiry, expires := claims["exp"].(float64)
	if !issued || !expires || expiry-issuedAt != domain.MCPStudentScopeProofTTLSeconds || issuedAt != float64(now.Unix()) {
		t.Fatalf("wrong time: %v %v", issuedAt, expiry)
	}
	if _, hasRole := claims["role"]; hasRole {
		t.Fatal("role-only assertion was promoted into scoped proof")
	}
	second, secondJTI, err := signer.Sign(context.Background(), testMCPStudentScopeSnapshot(now), requested)
	if err != nil || secondJTI == jti || second == proof {
		t.Fatalf("scope proof reused JTI: %v", err)
	}
	if !slices.Equal(requested, []string{"courses:read", "profile:read", "tasks:read"}) {
		t.Fatalf("signer mutated caller scopes: %v", requested)
	}
}

func TestMCPStudentScopeProofRejectsUnverifiedOrOverbroadGrant(t *testing.T) {
	_, privatePEM, publicPEM := reviewerKeyPEMs(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	signer, err := NewMCPStudentScopeProofSigner("auth-service", privatePEM, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	signer.clock = func() time.Time { return now }
	ctx := context.Background()
	base := testMCPStudentScopeSnapshot(now)
	request := []string{"courses:read", "tasks:read"}
	for name, mutate := range map[string]func(*domain.MCPExternalAuthGrantSnapshot){
		"wrong student":           func(s *domain.MCPExternalAuthGrantSnapshot) { s.StudentID = "not-uuid" },
		"wrong consent":           func(s *domain.MCPExternalAuthGrantSnapshot) { s.ConsentID = "" },
		"missing client":          func(s *domain.MCPExternalAuthGrantSnapshot) { s.ClientID = "" },
		"missing resource":        func(s *domain.MCPExternalAuthGrantSnapshot) { s.ResourceURI = "" },
		"revoked/expired consent": func(s *domain.MCPExternalAuthGrantSnapshot) { s.ConsentExpiresAt = now },
		"client scope removed":    func(s *domain.MCPExternalAuthGrantSnapshot) { s.ClientScopes = []string{"courses:read"} },
		"consent scope removed":   func(s *domain.MCPExternalAuthGrantSnapshot) { s.ConsentScopes = []string{"tasks:read"} },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := *base
			mutate(&snapshot)
			if proof, jti, err := signer.Sign(ctx, &snapshot, request); proof != "" || jti != "" || !errors.Is(err, ErrMCPStudentScopeProofUnavailable) {
				t.Fatalf("accepted invalid grant: proof=%q jti=%q err=%v", proof, jti, err)
			}
		})
	}
	for _, invalid := range [][]string{
		nil, {}, {"tasks:read", "courses:read"}, {"courses:read", "courses:read"},
		{"courses:read", "tasks:write"}, {"lessons:read"}, {"admin:read"},
		{"courses:read", "profile:read", "tasks:read", "other:read"},
	} {
		if proof, jti, err := signer.Sign(ctx, base, invalid); proof != "" || jti != "" || !errors.Is(err, ErrMCPStudentScopeProofUnavailable) {
			t.Fatalf("accepted invalid pilot scopes %v: %q %q %v", invalid, proof, jti, err)
		}
	}
	if proof, jti, err := signer.Sign(ctx, nil, request); proof != "" || jti != "" || err == nil {
		t.Fatalf("accepted nil verified snapshot: %q %q %v", proof, jti, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, invalidCtx := range []context.Context{nil, canceled} {
		if proof, jti, err := signer.Sign(invalidCtx, base, request); proof != "" || jti != "" || err == nil {
			t.Fatalf("accepted canceled/nil context: %q %q %v", proof, jti, err)
		}
	}
	var absent *MCPStudentScopeProofSigner
	if proof, jti, err := absent.Sign(ctx, base, request); proof != "" || jti != "" || err == nil {
		t.Fatalf("nil signer produced proof: %q %q %v", proof, jti, err)
	}
}

func TestMCPStudentScopeProofMissingOrInvalidKeysAndShortConsent(t *testing.T) {
	_, privatePEM, publicPEM := reviewerKeyPEMs(t)
	if signer, err := NewMCPStudentScopeProofSigner("auth-service", "", ""); signer != nil || err != nil {
		t.Fatalf("missing keys must disable signer: %v, %v", signer, err)
	}
	_, _, otherPublicPEM := reviewerKeyPEMs(t)
	for _, config := range []struct{ issuer, privateKey, publicKey string }{
		{"", privatePEM, publicPEM},
		{"auth-service", privatePEM, ""},
		{"auth-service", "", publicPEM},
		{"auth-service", privatePEM, otherPublicPEM},
		{"auth-service", "invalid", publicPEM},
	} {
		if signer, err := NewMCPStudentScopeProofSigner(config.issuer, config.privateKey, config.publicKey); signer != nil || !errors.Is(err, ErrMCPStudentScopeProofUnavailable) {
			t.Fatalf("accepted bad signing authority: %v, %v", signer, err)
		}
	}
	signer, err := NewMCPStudentScopeProofSigner("auth-service", privatePEM, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	signer.clock = func() time.Time { return now }
	snapshot := testMCPStudentScopeSnapshot(now)
	snapshot.ConsentExpiresAt = now.Add(12 * time.Second)
	proof, _, err := signer.Sign(context.Background(), snapshot, []string{"courses:read"})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(proof, claims)
	if err != nil || claims["exp"] != float64(now.Add(12*time.Second).Unix()) {
		t.Fatalf("proof outlived consent: claims=%v err=%v", claims, err)
	}
	snapshot.ConsentExpiresAt = now.Add(500 * time.Millisecond)
	if proof, _, err := signer.Sign(context.Background(), snapshot, []string{"courses:read"}); proof != "" || err == nil {
		t.Fatalf("accepted unusably short consent: %v", err)
	}
}
