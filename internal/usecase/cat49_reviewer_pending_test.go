package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/example/auth-service/internal/domain"
)

type cat49PendingStore struct {
	*t16Store
	pending bool
	unavailable bool
}

func (s *cat49PendingStore) SignupPrincipalPending(ctx context.Context, id string) (bool, error) {
	if s.unavailable {
		return false, errors.New("pending owner store unavailable")
	}
	if s.pending {
		return true, nil
	}
	return s.t16Store.SignupPrincipalPending(ctx, id)
}

type cat49SessionProbe struct {
	domain.RefreshTokenRepository
	id string
}

func (s cat49SessionProbe) FindActive(context.Context, string) (*domain.RefreshToken, error) {
	return &domain.RefreshToken{UserID:s.id}, nil
}

func TestCAT49PendingReviewerBlocksNewAndPreviouslyIssuedTokens(t *testing.T) {
	f := newT16(t)
	const id = "aaaabbbb-cccc-4ddd-8eee-ffffffffffff"
	user := &domain.AuthUser{ID:id, Email:"reviewer@example.invalid"}
	f.store.users[id] = user
	issued, err := f.service().issueTokens(context.Background(), user)
	if err != nil || issued == nil { t.Fatalf("baseline: %v", err) }
	ledger := &cat49PendingStore{t16Store:f.store, pending:true}
	svc := f.service()
	svc.completions = ledger
	svc.refresh = cat49SessionProbe{id:id}
	if token, err := svc.issueTokens(context.Background(), user); err == nil || token != nil {
		t.Fatal("pending reviewer issued tokens")
	}
	if proof, err := svc.VerifyToken(context.Background(), "cat49", issued.AccessToken); err == nil || proof != nil {
		t.Fatal("old token bypassed pending reviewer")
	}
	ledger.pending = false
	ledger.unavailable = true
	if proof, err := svc.VerifyToken(context.Background(), "cat49", issued.AccessToken); err == nil || proof != nil {
		t.Fatal("unavailable reviewer ledger allowed token")
	}
	ledger.unavailable = false
	if proof, err := svc.VerifyToken(context.Background(), "cat49", issued.AccessToken); err != nil || proof == nil {
		t.Fatalf("activated reviewer token denied: %v", err)
	}
}
