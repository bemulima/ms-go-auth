package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/example/auth-service/internal/domain"
)

// These are unit tests of the Auth issuer and its RBAC port, not evidence of
// any assignment in a running RBAC service.
func TestRoleClaimSignedForRBACConfirmedRoles(t *testing.T) {
	for _, role := range []string{"student", "student_pro", "teacher", "moderator", "admin"} {
		t.Run(role, func(t *testing.T) {
			f := newT16(t)
			const id = "11111111-1111-4111-8111-111111111111"
			client := &fixtureRoleClient{assigned: map[string]string{id: role}}
			svc := f.service()
			svc.rbacClient = client
			tokens, err := svc.issueTokens(context.Background(), &domain.AuthUser{ID: id, Email: "fixture@example.invalid"})
			if err != nil {
				t.Fatal(err)
			}
			parsed, claims, err := f.signer.Parse(tokens.AccessToken)
			if err != nil || !parsed.Valid {
				t.Fatal("access signature verification failed")
			}
			if claims["sub"] != id || claims["role"] != role {
				t.Fatalf("verified claims: sub=%v role=%v", claims["sub"], claims["role"])
			}
		})
	}
}

func TestRoleClaimNeverUsesUnverifiedDefault(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client *fixtureRoleClient
	}{
		{"rbac-unavailable", &fixtureRoleClient{checkErr: errors.New("rbac unavailable")}},
		{"rbac-no-assignment", &fixtureRoleClient{assigned: map[string]string{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newT16(t)
			f.cfg.DefaultRole = "admin"
			svc := f.service()
			svc.rbacClient = tc.client
			tokens, err := svc.issueTokens(context.Background(), &domain.AuthUser{ID: "test-only-principal", Email: "fixture@example.invalid"})
			if err != nil {
				t.Fatal(err)
			}
			parsed, claims, err := f.signer.Parse(tokens.AccessToken)
			if err != nil || !parsed.Valid {
				t.Fatal("access signature verification failed")
			}
			if _, ok := claims["role"]; ok {
				t.Fatal("unconfirmed role was signed")
			}
		})
	}
}

func TestRoleCandidatePriorityPreservesHigherRoles(t *testing.T) {
	got := collectRoleCandidates("student_pro")
	want := []string{"admin", "moderator", "teacher", "student_pro", "student", "user", "guest"}
	if len(got) != len(want) {
		t.Fatalf("candidates %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates %v", got)
		}
	}
}
