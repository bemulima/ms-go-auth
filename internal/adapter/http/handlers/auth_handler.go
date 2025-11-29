package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/example/auth-service/internal/usecase"
	res "github.com/example/auth-service/pkg/http"
)

type AuthHandler struct {
	service usecase.Service
}

func NewAuthHandler(s usecase.Service) *AuthHandler { return &AuthHandler{service: s} }

type signupStartRequest struct {
	Email string `json:"email"`
}

type signupVerifyRequest struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

type signinRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type emailChangeStartRequest struct {
	NewEmail string `json:"new_email"`
}

type emailChangeVerifyRequest struct {
	Code string `json:"code"`
}

type passwordResetStartRequest struct {
	Email string `json:"email"`
}

type passwordResetFinishRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

type oauthCallbackRequest struct {
	Code string `json:"code"`
}

func (h *AuthHandler) SignupStart(c echo.Context) error {
	req := new(signupStartRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	uuid, err := h.service.StartSignup(c.Request().Context(), requestIDFromCtx(c), req.Email)
	if err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "signup_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusAccepted, map[string]interface{}{"uuid": uuid})
}

func (h *AuthHandler) SignupVerify(c echo.Context) error {
	req := new(signupVerifyRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	user, tokens, err := h.service.VerifySignup(c.Request().Context(), requestIDFromCtx(c), req.Email, req.Code, req.Password)
	if err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "verification_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusOK, map[string]interface{}{"user": user, "tokens": tokens})
}

func (h *AuthHandler) SignIn(c echo.Context) error {
	req := new(signinRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	user, tokens, err := h.service.SignIn(c.Request().Context(), requestIDFromCtx(c), req.Email, req.Password)
	if err != nil {
		return res.ErrorJSON(c, http.StatusUnauthorized, "signin_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusOK, map[string]interface{}{"user": user, "tokens": tokens})
}

func (h *AuthHandler) Refresh(c echo.Context) error {
	req := new(refreshRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	tokens, err := h.service.Refresh(c.Request().Context(), requestIDFromCtx(c), req.RefreshToken)
	if err != nil {
		return res.ErrorJSON(c, http.StatusUnauthorized, "refresh_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusOK, tokens)
}

func (h *AuthHandler) EmailChangeStart(c echo.Context) error {
	req := new(emailChangeStartRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	userID := c.Get("user_id").(string)
	uuid, err := h.service.StartEmailChange(c.Request().Context(), requestIDFromCtx(c), userID, req.NewEmail)
	if err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "email_change_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusAccepted, map[string]string{"uuid": uuid})
}

func (h *AuthHandler) EmailChangeVerify(c echo.Context) error {
	req := new(emailChangeVerifyRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	user, err := h.service.VerifyEmailChange(c.Request().Context(), requestIDFromCtx(c), req.Code)
	if err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "email_change_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusOK, user)
}

func (h *AuthHandler) PasswordResetStart(c echo.Context) error {
	req := new(passwordResetStartRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	uuid, err := h.service.StartPasswordReset(c.Request().Context(), requestIDFromCtx(c), req.Email)
	if err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "password_reset_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusAccepted, map[string]string{"uuid": uuid})
}

func (h *AuthHandler) PasswordResetFinish(c echo.Context) error {
	req := new(passwordResetFinishRequest)
	if err := c.Bind(req); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	if err := h.service.FinishPasswordReset(c.Request().Context(), requestIDFromCtx(c), req.Email, req.Code, req.NewPassword); err != nil {
		return res.ErrorJSON(c, http.StatusBadRequest, "password_reset_failed", err.Error(), requestIDFromCtx(c), nil)
	}
	return res.JSON(c, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) OAuthCallback(c echo.Context) error {
	provider := c.Param("provider")
	_ = provider
	// placeholder: oauth exchange would happen here
	return res.ErrorJSON(c, http.StatusNotImplemented, "oauth_not_implemented", "oauth flow not implemented", requestIDFromCtx(c), nil)
}

func requestIDFromCtx(c echo.Context) string {
	if reqID := c.Response().Header().Get(echo.HeaderXRequestID); reqID != "" {
		return reqID
	}
	return c.Request().Header.Get(echo.HeaderXRequestID)
}
