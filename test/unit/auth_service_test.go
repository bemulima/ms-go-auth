package unit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/adapters/nats"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	pkglog "github.com/example/auth-service/pkg/log"
)

type mockUserRepo struct {
	users map[string]*domain.AuthUser
	next  int
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: map[string]*domain.AuthUser{}}
}

func (r *mockUserRepo) Create(_ context.Context, user *domain.AuthUser) error {
	if user.ID == "" {
		r.next++
		user.ID = fmt.Sprintf("user-%d", r.next)
	}
	r.users[user.ID] = user
	return nil
}

func (r *mockUserRepo) FindByEmail(_ context.Context, email string) (*domain.AuthUser, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

func (r *mockUserRepo) FindByID(_ context.Context, id string) (*domain.AuthUser, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (r *mockUserRepo) Update(_ context.Context, user *domain.AuthUser) error {
	r.users[user.ID] = user
	return nil
}

type mockIdentityRepo struct{}

func (mockIdentityRepo) FindByProvider(_ context.Context, _, _ string) (*domain.AuthIdentity, error) {
	return nil, gorm.ErrRecordNotFound
}
func (mockIdentityRepo) Create(_ context.Context, _ *domain.AuthIdentity) error { return nil }

type mockRefreshRepo struct {
	tokens map[string]domain.RefreshToken
}

func newMockRefreshRepo() *mockRefreshRepo {
	return &mockRefreshRepo{tokens: map[string]domain.RefreshToken{}}
}

func (r *mockRefreshRepo) Create(_ context.Context, token *domain.RefreshToken) error {
	r.tokens[token.RefreshTokenHash] = *token
	return nil
}

func (r *mockRefreshRepo) FindActive(_ context.Context, hash string) (*domain.RefreshToken, error) {
	tok, ok := r.tokens[hash]
	if !ok || tok.RevokedAt != nil || tok.ExpiresAt.Before(time.Now()) {
		return nil, gorm.ErrRecordNotFound
	}
	return &tok, nil
}

func (r *mockRefreshRepo) RevokeByHash(_ context.Context, hash string) error {
	if tok, ok := r.tokens[hash]; ok {
		now := time.Now()
		tok.RevokedAt = &now
		r.tokens[hash] = tok
	}
	return nil
}

type mockTarantool struct {
	signupUUID           string
	lastSignupEmail      string
	emailChangeUUID      string
	lastEmailChangeUser  string
	lastEmailChangeEmail string
	passwordResetUUID    string
	lastPasswordReset    string

	verifySignupErr         error
	verifyEmailChangeUserID string
	verifyEmailChangeEmail  string
	verifyEmailChangeErr    error
	verifyPasswordResetErr  error
}

func (m *mockTarantool) StartSignup(_ context.Context, email string) (string, error) {
	m.lastSignupEmail = email
	return m.signupUUID, nil
}

func (m *mockTarantool) VerifySignup(_ context.Context, _ string, _ string) error {
	return m.verifySignupErr
}

func (m *mockTarantool) StartEmailChange(_ context.Context, userID, newEmail string) (string, error) {
	m.lastEmailChangeUser = userID
	m.lastEmailChangeEmail = newEmail
	return m.emailChangeUUID, nil
}

func (m *mockTarantool) VerifyEmailChange(_ context.Context, _ string) (string, string, error) {
	return m.verifyEmailChangeUserID, m.verifyEmailChangeEmail, m.verifyEmailChangeErr
}

func (m *mockTarantool) StartPasswordReset(_ context.Context, email string) (string, error) {
	m.lastPasswordReset = email
	return m.passwordResetUUID, nil
}

func (m *mockTarantool) VerifyPasswordReset(_ context.Context, _ string, _ string) error {
	return m.verifyPasswordResetErr
}

type recordingUserClient struct {
	calls []struct {
		userID string
		source string
		typ    string
	}
}

func (r *recordingUserClient) CreateUser(_ context.Context, userID string, source string, typ string) error {
	r.calls = append(r.calls, struct {
		userID string
		source string
		typ    string
	}{userID: userID, source: source, typ: typ})
	return nil
}

type recordingRBACClient struct {
	calls []struct {
		userID string
		role   string
	}
}

func (r *recordingRBACClient) AssignRole(_ context.Context, userID, role string) error {
	r.calls = append(r.calls, struct {
		userID string
		role   string
	}{userID: userID, role: role})
	return nil
}

type testDeps struct {
	users      *mockUserRepo
	refresh    *mockRefreshRepo
	tara       *mockTarantool
	signer     usecase.JWTSigner
	cfg        *config.Config
	userClient natsadapter.UserClient
	rbacClient natsadapter.RBACClient
}

func newTestService(t *testing.T) (usecase.Service, *testDeps) {
	return newTestServiceWithClients(t, nil, nil)
}

func newTestServiceWithClients(t *testing.T, userClient natsadapter.UserClient, rbacClient natsadapter.RBACClient) (usecase.Service, *testDeps) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:   "test-secret",
		JWTIssuer:   "auth",
		JWTAudience: "frontend",
		AccessTTL:   time.Minute,
		RefreshTTL:  time.Hour,
		DefaultRole: "user",
	}
	signer, err := usecase.NewJWTSigner(cfg)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	users := newMockUserRepo()
	refresh := newMockRefreshRepo()
	tara := &mockTarantool{
		signupUUID:              "signup-uuid",
		emailChangeUUID:         "email-change-uuid",
		passwordResetUUID:       "pwd-reset-uuid",
		verifyEmailChangeUserID: "user-1",
		verifyEmailChangeEmail:  "new@example.com",
	}
	svc := usecase.NewAuthService(cfg, pkglog.New("test"), users, mockIdentityRepo{}, refresh, tara, userClient, rbacClient, signer)
	return svc, &testDeps{users: users, refresh: refresh, tara: tara, signer: signer, cfg: cfg, userClient: userClient, rbacClient: rbacClient}
}

func TestStartSignup(t *testing.T) {
	svc, deps := newTestService(t)
	// existing user
	_ = deps.users.Create(context.Background(), &domain.AuthUser{Email: "user@example.com"})
	if _, err := svc.StartSignup(context.Background(), "trace", "user@example.com"); err == nil {
		t.Fatalf("expected error for existing user")
	}
	// new user
	uuid, err := svc.StartSignup(context.Background(), "trace", "New@Example.com")
	if err != nil {
		t.Fatalf("start signup: %v", err)
	}
	if uuid != deps.tara.signupUUID {
		t.Fatalf("unexpected uuid: %s", uuid)
	}
	if deps.tara.lastSignupEmail != "new@example.com" {
		t.Fatalf("email not normalized: %s", deps.tara.lastSignupEmail)
	}
}

func TestVerifySignupCreatesUserAndTokens(t *testing.T) {
	svc, deps := newTestService(t)
	user, tokens, err := svc.VerifySignup(context.Background(), "trace", "User@Example.com", "code", "password123")
	if err != nil {
		t.Fatalf("verify signup: %v", err)
	}
	if user == nil || tokens == nil {
		t.Fatalf("expected user and tokens")
	}
	if user.Email != "user@example.com" {
		t.Fatalf("expected normalized email, got %s", user.Email)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("tokens should be issued")
	}
	if len(deps.refresh.tokens) == 0 {
		t.Fatalf("refresh token not stored")
	}
}

func TestVerifySignupNotifiesUserAndRBAC(t *testing.T) {
	userClient := &recordingUserClient{}
	rbacClient := &recordingRBACClient{}
	svc, deps := newTestServiceWithClients(t, userClient, rbacClient)

	user, _, err := svc.VerifySignup(context.Background(), "trace", "notify@example.com", "code", "password123")
	if err != nil {
		t.Fatalf("verify signup: %v", err)
	}
	if user == nil {
		t.Fatalf("user is nil")
	}
	if len(userClient.calls) != 1 {
		t.Fatalf("expected CreateUser to be called once, got %d", len(userClient.calls))
	}
	call := userClient.calls[0]
	if call.userID != user.ID || call.source != "auth" || call.typ != "signup" {
		t.Fatalf("CreateUser call mismatch: %+v", call)
	}
	if len(rbacClient.calls) != 1 {
		t.Fatalf("expected AssignRole to be called once, got %d", len(rbacClient.calls))
	}
	rbacCall := rbacClient.calls[0]
	if rbacCall.userID != user.ID || rbacCall.role != deps.cfg.DefaultRole {
		t.Fatalf("AssignRole call mismatch: %+v", rbacCall)
	}
}

func TestSignIn(t *testing.T) {
	svc, deps := newTestService(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	_ = deps.users.Create(context.Background(), &domain.AuthUser{Email: "user@example.com", PasswordHash: string(hash)})
	user, tokens, err := svc.SignIn(context.Background(), "trace", "user@example.com", "secret123")
	if err != nil {
		t.Fatalf("signin: %v", err)
	}
	if user.LastLoginAt == nil {
		t.Fatalf("last login not set")
	}
	if tokens.AccessToken == "" {
		t.Fatalf("access token missing")
	}
}

func TestRefresh(t *testing.T) {
	svc, deps := newTestService(t)
	user := &domain.AuthUser{ID: "user-1", Email: "user@example.com"}
	_ = deps.users.Create(context.Background(), user)
	jti := "jti-1"
	refreshTok, err := deps.signer.SignRefreshToken(user.ID, jti, deps.cfg.RefreshTTL)
	if err != nil {
		t.Fatalf("sign refresh: %v", err)
	}
	deps.refresh.Create(context.Background(), &domain.RefreshToken{
		UserID:           user.ID,
		RefreshTokenHash: hashToken(jti),
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	tokens, err := svc.Refresh(context.Background(), "trace", refreshTok)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatalf("expected new access token")
	}
}

func TestRefreshRejectsMismatchedSession(t *testing.T) {
	svc, deps := newTestService(t)
	user := &domain.AuthUser{ID: "user-1", Email: "user@example.com"}
	_ = deps.users.Create(context.Background(), user)
	jti := "jti-2"
	refreshTok, err := deps.signer.SignRefreshToken(user.ID, jti, deps.cfg.RefreshTTL)
	if err != nil {
		t.Fatalf("sign refresh: %v", err)
	}
	deps.refresh.Create(context.Background(), &domain.RefreshToken{
		UserID:           "other-user",
		RefreshTokenHash: hashToken(jti),
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	if _, err := svc.Refresh(context.Background(), "trace", refreshTok); err == nil {
		t.Fatalf("expected error for mismatched session")
	}
}

func TestEmailChangeFlow(t *testing.T) {
	svc, deps := newTestService(t)
	user := &domain.AuthUser{ID: "user-1", Email: "user@example.com"}
	_ = deps.users.Create(context.Background(), user)

	uuid, err := svc.StartEmailChange(context.Background(), "trace", user.ID, "NewEmail@example.com")
	if err != nil {
		t.Fatalf("start email change: %v", err)
	}
	if uuid != deps.tara.emailChangeUUID {
		t.Fatalf("unexpected uuid: %s", uuid)
	}
	if deps.tara.lastEmailChangeEmail != "newemail@example.com" {
		t.Fatalf("email not normalized: %s", deps.tara.lastEmailChangeEmail)
	}

	updated, err := svc.VerifyEmailChange(context.Background(), "trace", "code")
	if err != nil {
		t.Fatalf("verify email change: %v", err)
	}
	if updated.Email != "new@example.com" {
		t.Fatalf("email not updated: %s", updated.Email)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	svc, deps := newTestService(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("oldpass123"), bcrypt.DefaultCost)
	_ = deps.users.Create(context.Background(), &domain.AuthUser{Email: "user@example.com", PasswordHash: string(hash)})

	uuid, err := svc.StartPasswordReset(context.Background(), "trace", "user@example.com")
	if err != nil {
		t.Fatalf("start password reset: %v", err)
	}
	if uuid != deps.tara.passwordResetUUID {
		t.Fatalf("unexpected uuid: %s", uuid)
	}
	if deps.tara.lastPasswordReset != "user@example.com" {
		t.Fatalf("email not normalized: %s", deps.tara.lastPasswordReset)
	}

	if err := svc.FinishPasswordReset(context.Background(), "trace", "user@example.com", "code", "newpass123"); err != nil {
		t.Fatalf("finish password reset: %v", err)
	}
	updated, _ := deps.users.FindByEmail(context.Background(), "user@example.com")
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("newpass123")) != nil {
		t.Fatalf("password was not updated")
	}
}

func hashToken(jti string) string {
	return fmt.Sprintf("rt:%s", jti)
}
