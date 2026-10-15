package usecase

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/example/auth-service/internal/domain"
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"time"
)

var errEmailCodeCollision = errors.New("verification code allocation conflict")

type EmailCodes struct {
	store       domain.VerificationRepository
	mail        domain.Mailer
	key         []byte
	originLimit int
}

// EnableEmailCodes configures the approved code/grant workflow without replacing persistence or provisioning.
func EnableEmailCodes(service Service, store domain.VerificationRepository, mail domain.Mailer, key string, originLimit int) error {
	s, ok := service.(*authService)
	if !ok || store == nil || mail == nil || len(key) < 32 || originLimit < 1 {
		return errors.New("email-code configuration unavailable")
	}
	s.codes = &EmailCodes{store, mail, []byte(key), originLimit}
	return nil
}
func (c *EmailCodes) digest(purpose, value string) string {
	h := hmac.New(sha256.New, c.key)
	_, _ = h.Write([]byte(purpose + "\x00" + value))
	return hex.EncodeToString(h.Sum(nil))
}
func (c *EmailCodes) call(ctx context.Context, action string, args ...interface{}) ([]interface{}, error) {
	r, e := c.store.Execute(ctx, action, args)
	if e != nil || len(r) < 1 {
		return nil, errors.New("verification unavailable")
	}
	if r[0] == "code_conflict" {
		return nil, errEmailCodeCollision
	}
	if r[0] != "ok" {
		return nil, fmt.Errorf("verification %v", r[0])
	}
	if len(r) < 2 {
		return nil, errors.New("verification unavailable")
	}
	tuple, ok := r[1].([]interface{})
	if !ok {
		return nil, errors.New("verification unavailable")
	}
	return tuple, nil
}
func (s *authService) StartEmailCode(ctx context.Context, purpose, email, origin string) error {
	if s.codes == nil {
		return errors.New("email-code workflow unavailable")
	}
	email = normalizeEmail(email)
	if err := validateEmail(email); err != nil {
		return err
	}
	if purpose != "registration" && purpose != "reset" {
		return errors.New("invalid purpose")
	}
	u, err := s.users.FindByEmail(ctx, email)
	if purpose == "registration" {
		if err == nil {
			return errors.New("account exists")
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
	}
	// Unknown and OAuth-only addresses receive the same public response and no code.
	if purpose == "reset" && (errors.Is(err, domain.ErrNotFound) || (err == nil && u.PasswordHash == nil)) {
		return nil
	}
	if purpose == "reset" && err != nil {
		return err
	}
	for attempt := 0; attempt < 10; attempt++ {
		n, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			return errors.New("verification unavailable")
		}
		code := fmt.Sprintf("%06d", n.Int64())
		_, err = s.codes.call(ctx, "code_start", purpose, email, s.codes.digest(purpose, email+"\x00"+code), time.Now().Unix(), s.codes.digest("origin", origin), s.codes.originLimit)
		if errors.Is(err, errEmailCodeCollision) {
			continue
		}
		if err != nil {
			return err
		}
		return s.codes.mail.Send(ctx, email, "Authentication "+purpose+" code", "Your verification code: "+code+". Valid for 10 minutes.")
	}
	return errors.New("verification unavailable")
}
func (s *authService) VerifyEmailCode(ctx context.Context, purpose, email, code string) (string, error) {
	if s.codes == nil {
		return "", errors.New("email-code workflow unavailable")
	}
	email = normalizeEmail(email)
	if len(code) != 6 {
		return "", errors.New("invalid code")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return "", errors.New("invalid code")
		}
	}
	grant, err := GenerateJTI()
	if err != nil {
		return "", err
	}
	_, err = s.codes.call(ctx, "code_verify", purpose, email, s.codes.digest(purpose, email+"\x00"+code), time.Now().Unix(), s.codes.digest("grant", grant))
	if err != nil {
		return "", err
	}
	return grant, nil
}
func (s *authService) CompleteEmailRegistration(ctx context.Context, email, grant, password string) (*Tokens, error) {
	if s.codes == nil {
		return nil, errors.New("email-code workflow unavailable")
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	email = normalizeEmail(email)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	tuple, err := s.codes.call(ctx, "grant_consume", "registration", email, s.codes.digest("grant", grant), time.Now().Unix())
	if err != nil {
		return nil, err
	}
	operation, err := GenerateJTI()
	if err != nil {
		return nil, err
	}
	principal, err := GenerateJTI()
	if err != nil {
		return nil, err
	}
	op, err := s.completions.BeginSignupCompletion(ctx, email, s.codes.digest("registration-operation", grant), operation, principal)
	if err != nil {
		return nil, err
	}
	expiry, ok := codeNumber(tuple[0])
	if !ok {
		return nil, errors.New("invalid grant expiry")
	}
	receipt := &domain.SignupProofReceipt{OperationID: op.OperationID, Email: email, PasswordHash: string(hash), ExpiresAt: time.Unix(expiry, 0)}
	if _, err = s.completions.StoreSignupReceipt(ctx, op.OperationID, receipt); err != nil {
		return nil, err
	}
	user, err := s.completions.EnsureSignupPrincipal(ctx, op.OperationID)
	if err != nil {
		return nil, err
	}
	if err = s.provisionSignupActor(ctx, user, op.OperationID); err != nil {
		return nil, err
	}
	won, err := s.completions.CompleteSignup(ctx, op.OperationID, time.Now(), true)
	if err != nil || !won {
		return nil, errors.New("registration completion failed")
	}
	return s.issueTokens(ctx, user)
}
func codeNumber(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}
func (s *authService) CompleteEmailReset(ctx context.Context, email, grant, password string) error {
	if s.codes == nil {
		return errors.New("email-code workflow unavailable")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	email = normalizeEmail(email)
	repo, ok := s.users.(domain.PasswordResetRepository)
	if !ok {
		return errors.New("reset persistence unavailable")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err = s.codes.call(ctx, "grant_consume", "reset", email, s.codes.digest("grant", grant), time.Now().Unix()); err != nil {
		return err
	}
	if err = repo.ResetPassword(ctx, email, string(hash), time.Now().UTC()); err != nil {
		return err
	}
	return s.codes.mail.Send(ctx, email, "Password changed", "Your password was changed. Previous sessions were revoked.")
}
