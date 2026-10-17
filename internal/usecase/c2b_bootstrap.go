package usecase

import (
	"context"
	"errors"
	"github.com/example/auth-service/internal/domain"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type C2BBootstrap struct {
	Store domain.C2BBootstrapStore
	Roles domain.RoleClient
}

func (b C2BBootstrap) Prepare(ctx context.Context, i domain.C2BIntent, s domain.C2BSignedIntent) error {
	if !i.Valid() || b.Store == nil {
		return errors.New("bootstrap denied")
	}
	return b.Store.SaveC2BIntent(ctx, i, s)
}
func (b C2BBootstrap) Finalize(ctx context.Context, i domain.C2BIntent, r domain.C2BReceipt, password string) error {
	if !i.Valid() || !r.Valid() || r.Intent != i || b.Store == nil || b.Roles == nil || len(password) < 8 || len(password) > 72 {
		return errors.New("bootstrap denied")
	}
	ok, e := b.Roles.CheckRole(ctx, i.Principal, i.Role)
	if e != nil || !ok {
		return errors.New("independent role readback failed")
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	h := string(hash)
	u, e := b.Store.FinalizeC2B(ctx, i, r, &domain.AuthUser{ID: i.Principal, Email: i.Email, PasswordHash: &h, PasswordUpdatedAt: &now, EmailVerified: true})
	if e != nil {
		return e
	}
	if u == nil || u.ID != i.Principal || u.Email != i.Email || u.PasswordHash == nil || !u.EmailVerified || bcrypt.CompareHashAndPassword([]byte(*u.PasswordHash), []byte(password)) != nil {
		return errors.New("bootstrap replay credential conflict")
	}
	return nil
}
func (s *authService) c2bRole(ctx context.Context, id string) (string, error) {
	if !s.cfg.C2BProofEnabled || id != domain.C2BMentorID {
		return "", nil
	}
	if !s.cfg.C2BProofExpires.After(time.Now()) {
		return "", errors.New("isolated mentor authority expired")
	}
	if e := s.cfg.ValidateC2BProof(); e != nil {
		return "", e
	}
	reader, ok := s.users.(domain.C2BMentorAuditReader)
	if !ok {
		return "", errors.New("mentor bootstrap audit unavailable")
	}
	valid, e := reader.C2BMentorEligible(ctx, id)
	if e != nil || !valid || s.rbacClient == nil {
		return "", errors.New("mentor audit denied")
	}
	valid, e = s.rbacClient.CheckRole(ctx, id, "mentor")
	if e != nil || !valid {
		return "", errors.New("mentor authority readback denied")
	}
	return "MENTOR", nil
}
