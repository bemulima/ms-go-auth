package usecase

import (
	"context"
	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	"testing"
	"time"
)

type mentorUsers struct {
	domain.AuthUserRepository
	eligible bool
}

func (m mentorUsers) C2BMentorEligible(context.Context, string) (bool, error) { return m.eligible, nil }

type mentorRoles bool

func (m mentorRoles) AssignRole(context.Context, string, string) error        { return nil }
func (m mentorRoles) CheckRole(context.Context, string, string) (bool, error) { return bool(m), nil }
func TestMentorClaimRequiresAuditedIsolatedAuthority(t *testing.T) {
	cfg := &config.Config{C2BProofEnabled: true, C2BProofExpires: time.Now().Add(time.Hour), AppEnv: "c2b-proof", HTTPHost: "127.0.0.1", DBHost: "127.0.0.1", DBUser: "c2b_auth_runtime", DBName: "c2b_auth_20261016"}
	s := authService{cfg: cfg, users: mentorUsers{eligible: true}, rbacClient: mentorRoles(true)}
	if role, e := s.c2bRole(context.Background(), domain.C2BMentorID); e != nil || role != "MENTOR" {
		t.Fatal(role, e)
	}
	s.users = mentorUsers{eligible: false}
	if _, e := s.c2bRole(context.Background(), domain.C2BMentorID); e == nil {
		t.Fatal("unaudited mentor claim")
	}
	s.users = mentorUsers{eligible: true}
	s.rbacClient = mentorRoles(false)
	if _, e := s.c2bRole(context.Background(), domain.C2BMentorID); e == nil {
		t.Fatal("unassigned mentor claim")
	}
	s.rbacClient = mentorRoles(true)
	cfg.C2BProofExpires = time.Now().Add(-time.Second)
	if _, e := s.c2bRole(context.Background(), domain.C2BMentorID); e == nil {
		t.Fatal("expired authority accepted")
	}
	cfg.C2BProofExpires = time.Now().Add(time.Hour)
	cfg.AppEnv = "production"
	if _, e := s.c2bRole(context.Background(), domain.C2BMentorID); e == nil {
		t.Fatal("production mentor")
	}
	if role, e := s.c2bRole(context.Background(), domain.C2BLearnerID); e != nil || role != "" {
		t.Fatal("learner promoted")
	}
}

type mentorStore struct {
	user  *domain.AuthUser
	calls int
}

func (m *mentorStore) SaveC2BIntent(context.Context, domain.C2BIntent, domain.C2BSignedIntent) error {
	return nil
}
func (m *mentorStore) LoadC2BIntent(context.Context, string) (domain.C2BSignedIntent, error) {
	return domain.C2BSignedIntent{}, nil
}
func (m *mentorStore) FinalizeC2B(_ context.Context, _ domain.C2BIntent, _ domain.C2BReceipt, u *domain.AuthUser) (*domain.AuthUser, error) {
	m.calls++
	if m.user == nil {
		m.user = u
	}
	return m.user, nil
}
func TestBootstrapRoleReadbackBeforeCredentialAndReplayNeverResets(t *testing.T) {
	i, _ := domain.C2BActor("mentor")
	store := &mentorStore{}
	b := C2BBootstrap{Store: store, Roles: mentorRoles(false)}
	if b.Finalize(context.Background(), i, domain.C2BReceiptFor(i), "private-test-password") == nil || store.calls != 0 {
		t.Fatal("credential before role authority")
	}
	b.Roles = mentorRoles(true)
	if e := b.Finalize(context.Background(), i, domain.C2BReceiptFor(i), "private-test-password"); e != nil {
		t.Fatal(e)
	}
	hash := *store.user.PasswordHash
	if e := b.Finalize(context.Background(), i, domain.C2BReceiptFor(i), "changed-test-password"); e == nil || *store.user.PasswordHash != hash {
		t.Fatal("replay reset credential")
	}
}
