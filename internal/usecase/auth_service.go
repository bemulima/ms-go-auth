package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/adapters/nats"
	"github.com/example/auth-service/internal/adapters/postgres"
	taraclient "github.com/example/auth-service/internal/adapters/tarantool"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/tokenverify"
	pkglog "github.com/example/auth-service/pkg/log"
)

var (
	errInvalidCredentials = errors.New("invalid credentials")
)

type Service interface {
	StartSignup(ctx context.Context, traceID, email, password string) error
	VerifySignup(ctx context.Context, traceID, email, code string) (*domain.AuthUser, *Tokens, error)
	SignIn(ctx context.Context, traceID, email, password string) (*domain.AuthUser, *Tokens, error)
	Refresh(ctx context.Context, traceID, refreshToken string) (*Tokens, error)
	StartEmailChange(ctx context.Context, traceID, userID, newEmail string) (string, error)
	VerifyEmailChange(ctx context.Context, traceID, code string) (*domain.AuthUser, error)
	StartPasswordReset(ctx context.Context, traceID, email string) (string, error)
	FinishPasswordReset(ctx context.Context, traceID, email, code, newPassword string) error
	ChangePassword(ctx context.Context, traceID, userID, oldPassword, newPassword string) error
	VerifyToken(ctx context.Context, traceID, token string) (*VerificationResult, error)
}

type authService struct {
	cfg        *config.Config
	logger     pkglog.Logger
	users      repo.AuthUserRepository
	identities repo.AuthIdentityRepository
	refresh    repo.RefreshTokenRepository
	tarantoool taraclient.Client
	userClient natsadapter.UserClient
	rbacClient natsadapter.RBACClient
	signer     JWTSigner
}

func NewAuthService(cfg *config.Config, logger pkglog.Logger, users repo.AuthUserRepository, identities repo.AuthIdentityRepository, refresh repo.RefreshTokenRepository, tara taraclient.Client, userClient natsadapter.UserClient, rbacClient natsadapter.RBACClient, signer JWTSigner) Service {
	return &authService{cfg: cfg, logger: logger, users: users, identities: identities, refresh: refresh, tarantoool: tara, userClient: userClient, rbacClient: rbacClient, signer: signer}
}

func (s *authService) StartSignup(ctx context.Context, traceID, email, password string) error {
	norm := normalizeEmail(email)
	if err := validateEmail(norm); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	if _, err := s.users.FindByEmail(ctx, norm); err == nil {
		return fmt.Errorf("user already exists")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.tarantoool.StartSignup(ctx, norm, string(hash)); err != nil {
		return err
	}

	s.logger.Info().Str("trace_id", traceID).Str("email", norm).Msg("signup initiated")
	return nil
}

func (s *authService) VerifySignup(ctx context.Context, traceID, email, code string) (*domain.AuthUser, *Tokens, error) {
	norm := normalizeEmail(email)
	if err := validateEmail(norm); err != nil {
		return nil, nil, err
	}

	passwordHash, err := s.tarantoool.VerifySignup(ctx, norm, code)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(passwordHash) == "" {
		return nil, nil, fmt.Errorf("password hash missing")
	}

	user := &domain.AuthUser{Email: norm, PasswordHash: passwordHash}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, nil, err
	}
	if s.userClient != nil {
		_ = s.userClient.CreateUser(ctx, user.ID, user.Email, "auth", "signup")
	}
	if s.rbacClient != nil {
		_ = s.rbacClient.AssignRole(ctx, user.ID, s.cfg.DefaultRole)
	}
	tokens, err := s.issueTokens(user)
	if err != nil {
		return nil, nil, err
	}
	s.logger.Info().Str("trace_id", traceID).Str("user_id", user.ID).Msg("signup verified")
	return user, tokens, nil
}

func (s *authService) SignIn(ctx context.Context, traceID, email, password string) (*domain.AuthUser, *Tokens, error) {
	norm := normalizeEmail(email)
	user, err := s.users.FindByEmail(ctx, norm)
	if err != nil {
		return nil, nil, errInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, nil, errInvalidCredentials
	}
	now := time.Now()
	user.LastLoginAt = &now
	_ = s.users.Update(ctx, user)
	tokens, err := s.issueTokens(user)
	if err != nil {
		return nil, nil, err
	}
	s.logger.Info().Str("trace_id", traceID).Str("user_id", user.ID).Msg("signin")
	return user, tokens, nil
}

func (s *authService) Refresh(ctx context.Context, traceID, refreshToken string) (*Tokens, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, errInvalidCredentials
	}
	tok, claims, err := s.signer.Parse(refreshToken)
	if err != nil || tok == nil || !tok.Valid {
		return nil, errInvalidCredentials
	}
	if typ, _ := claims["typ"].(string); typ != "refresh" {
		return nil, errInvalidCredentials
	}
	jti, _ := claims["jti"].(string)
	sub, _ := claims["sub"].(string)
	if jti == "" || sub == "" {
		return nil, errInvalidCredentials
	}
	hash := hashToken(jti)
	session, err := s.refresh.FindActive(ctx, hash)
	if err != nil {
		return nil, errInvalidCredentials
	}
	if session.UserID != sub {
		return nil, errInvalidCredentials
	}
	user, err := s.users.FindByID(ctx, sub)
	if err != nil {
		return nil, errInvalidCredentials
	}
	return s.issueTokens(user)
}

func (s *authService) StartEmailChange(ctx context.Context, traceID, userID, newEmail string) (string, error) {
	norm := normalizeEmail(newEmail)
	if err := validateEmail(norm); err != nil {
		return "", err
	}
	uuid, err := s.tarantoool.StartEmailChange(ctx, userID, norm)
	if err != nil {
		return "", err
	}
	s.logger.Info().Str("trace_id", traceID).Str("user_id", userID).Msg("email change started")
	return uuid, nil
}

func (s *authService) VerifyEmailChange(ctx context.Context, traceID, code string) (*domain.AuthUser, error) {
	userID, newEmail, err := s.tarantoool.VerifyEmailChange(ctx, code)
	if err != nil {
		return nil, err
	}
	norm := normalizeEmail(newEmail)
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	user.Email = norm
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	s.logger.Info().Str("trace_id", traceID).Str("user_id", user.ID).Msg("email change verified")
	return user, nil
}

func (s *authService) StartPasswordReset(ctx context.Context, traceID, email string) (string, error) {
	norm := normalizeEmail(email)
	if err := validateEmail(norm); err != nil {
		return "", err
	}
	if _, err := s.users.FindByEmail(ctx, norm); err != nil {
		return "", errInvalidCredentials
	}
	uuid, err := s.tarantoool.StartPasswordReset(ctx, norm)
	if err != nil {
		return "", err
	}
	s.logger.Info().Str("trace_id", traceID).Str("email", norm).Msg("password reset start")
	return uuid, nil
}

func (s *authService) FinishPasswordReset(ctx context.Context, traceID, email, code, newPassword string) error {
	norm := normalizeEmail(email)
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	if err := s.tarantoool.VerifyPasswordReset(ctx, norm, code); err != nil {
		return err
	}
	user, err := s.users.FindByEmail(ctx, norm)
	if err != nil {
		return errInvalidCredentials
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hash)
	user.PasswordUpdatedAt = time.Now()
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}
	s.logger.Info().Str("trace_id", traceID).Str("user_id", user.ID).Msg("password reset finished")
	return nil
}

func (s *authService) ChangePassword(ctx context.Context, traceID, userID, oldPassword, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return errInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return errInvalidCredentials
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hash)
	user.PasswordUpdatedAt = time.Now()
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}
	s.logger.Info().Str("trace_id", traceID).Str("user_id", user.ID).Msg("password changed")
	return nil
}

func (s *authService) VerifyToken(ctx context.Context, traceID, token string) (*VerificationResult, error) {
	result, err := tokenverify.Verify(s.signer, token, time.Now)
	if err != nil {
		return nil, err
	}
	s.logger.Info().Str("trace_id", traceID).Str("user_id", result.UserID).Msg("token verified")
	return result, nil
}

func (s *authService) issueTokens(user *domain.AuthUser) (*Tokens, error) {
	claims := map[string]interface{}{"email": user.Email}
	access, err := s.signer.SignAccessToken(user.ID, claims, s.cfg.AccessTTL)
	if err != nil {
		return nil, err
	}
	jti, err := GenerateJTI()
	if err != nil {
		return nil, err
	}
	refresh, err := s.signer.SignRefreshToken(user.ID, jti, s.cfg.RefreshTTL)
	if err != nil {
		return nil, err
	}
	// persist refresh
	s.refresh.Create(context.Background(), &domain.RefreshToken{UserID: user.ID, RefreshTokenHash: hashToken(jti), ExpiresAt: time.Now().Add(s.cfg.RefreshTTL)})
	return &Tokens{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(s.cfg.AccessTTL.Seconds())}, nil
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func validateEmail(email string) error {
	if !strings.Contains(email, "@") || len(email) > 255 {
		return fmt.Errorf("invalid email")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password too short")
	}
	return nil
}

func hashToken(jti string) string {
	return fmt.Sprintf("rt:%s", jti)
}
