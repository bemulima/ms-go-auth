package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	res "github.com/example/auth-service/pkg/http"
)

type mockAuthService struct {
	startSignupFn        func(email string) (string, error)
	verifySignupFn       func(email, code, password string) (*domain.AuthUser, *usecase.Tokens, error)
	signInFn             func(email, password string) (*domain.AuthUser, *usecase.Tokens, error)
	refreshFn            func(token string) (*usecase.Tokens, error)
	startEmailChangeFn   func(userID, email string) (string, error)
	verifyEmailChangeFn  func(code string) (*domain.AuthUser, error)
	startPasswordResetFn func(email string) (string, error)
	finishPasswordFn     func(email, code, newPass string) error
	verifyTokenFn        func(token string) (*usecase.VerificationResult, error)
}

func (m *mockAuthService) StartSignup(_ context.Context, _ string, email string) (string, error) {
	return m.startSignupFn(email)
}

func (m *mockAuthService) VerifySignup(_ context.Context, _ string, email, code, password string) (*domain.AuthUser, *usecase.Tokens, error) {
	return m.verifySignupFn(email, code, password)
}

func (m *mockAuthService) SignIn(_ context.Context, _ string, email, password string) (*domain.AuthUser, *usecase.Tokens, error) {
	return m.signInFn(email, password)
}

func (m *mockAuthService) Refresh(_ context.Context, _ string, token string) (*usecase.Tokens, error) {
	return m.refreshFn(token)
}

func (m *mockAuthService) StartEmailChange(_ context.Context, _ string, userID, newEmail string) (string, error) {
	return m.startEmailChangeFn(userID, newEmail)
}

func (m *mockAuthService) VerifyEmailChange(_ context.Context, _ string, code string) (*domain.AuthUser, error) {
	return m.verifyEmailChangeFn(code)
}

func (m *mockAuthService) StartPasswordReset(_ context.Context, _ string, email string) (string, error) {
	return m.startPasswordResetFn(email)
}

func (m *mockAuthService) FinishPasswordReset(_ context.Context, _ string, email, code, newPassword string) error {
	return m.finishPasswordFn(email, code, newPassword)
}

func (m *mockAuthService) VerifyToken(_ context.Context, _ string, token string) (*usecase.VerificationResult, error) {
	return m.verifyTokenFn(token)
}

// ensure interface compliance
var _ usecase.Service = (*mockAuthService)(nil)

func TestSignupStartSuccess(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		startSignupFn: func(email string) (string, error) {
			if email != "user@example.com" {
				t.Fatalf("unexpected email: %s", email)
			}
			return "uuid-1", nil
		},
	}
	h := NewAuthHandler(svc)

	body, _ := json.Marshal(map[string]string{"email": "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.SignupStart(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp res.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data := resp.Data.(map[string]interface{})
	if data["uuid"] != "uuid-1" {
		t.Fatalf("unexpected uuid: %+v", data)
	}
}

func TestSignupStartFailure(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		startSignupFn: func(_ string) (string, error) {
			return "", echo.NewHTTPError(http.StatusBadRequest, "fail")
		},
	}
	h := NewAuthHandler(svc)

	body, _ := json.Marshal(map[string]string{"email": "bad"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_ = h.SignupStart(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp res.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error.Code != "signup_failed" {
		t.Fatalf("unexpected code: %s", resp.Error.Code)
	}
}

func TestSignInSuccess(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		signInFn: func(email, password string) (*domain.AuthUser, *usecase.Tokens, error) {
			if email != "user@example.com" || password != "secret" {
				t.Fatalf("unexpected credentials")
			}
			return &domain.AuthUser{ID: "u1", Email: email}, &usecase.Tokens{AccessToken: "a", RefreshToken: "r", ExpiresIn: 60}, nil
		},
	}
	h := NewAuthHandler(svc)
	body, _ := json.Marshal(map[string]string{"email": "user@example.com", "password": "secret"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.SignIn(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRefreshUnauthorized(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		refreshFn: func(_ string) (*usecase.Tokens, error) {
			return nil, errors.New("bad")
		},
	}
	h := NewAuthHandler(svc)
	body, _ := json.Marshal(map[string]string{"refresh_token": "invalid"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_ = h.Refresh(c)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp res.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error.Code != "refresh_failed" {
		t.Fatalf("unexpected code: %s", resp.Error.Code)
	}
}

func TestSignupVerifyError(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		verifySignupFn: func(_, _, _ string) (*domain.AuthUser, *usecase.Tokens, error) {
			return nil, nil, errors.New("verify fail")
		},
	}
	h := NewAuthHandler(svc)
	body, _ := json.Marshal(map[string]string{"email": "user@example.com", "code": "c", "password": "pass"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_ = h.SignupVerify(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestVerifyTokenSuccess(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		verifyTokenFn: func(token string) (*usecase.VerificationResult, error) {
			if token != "good" {
				t.Fatalf("unexpected token: %s", token)
			}
			return &usecase.VerificationResult{UserID: "u1", Email: "user@example.com", Claims: map[string]any{"role": "student"}}, nil
		},
	}
	h := NewAuthHandler(svc)
	body, _ := json.Marshal(map[string]string{"token": "good"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.VerifyToken(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestVerifyTokenFailure(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		verifyTokenFn: func(_ string) (*usecase.VerificationResult, error) {
			return nil, errors.New("invalid_token")
		},
	}
	h := NewAuthHandler(svc)
	body, _ := json.Marshal(map[string]string{"token": "bad"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_ = h.VerifyToken(c)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestEmailChangeStart(t *testing.T) {
	e := echo.New()
	svc := &mockAuthService{
		startEmailChangeFn: func(userID, email string) (string, error) {
			if userID != "u1" || email != "new@example.com" {
				t.Fatalf("unexpected input")
			}
			return "uuid-email", nil
		},
	}
	h := NewAuthHandler(svc)
	body, _ := json.Marshal(map[string]string{"new_email": "new@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user_id", "u1")

	if err := h.EmailChangeStart(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
}
