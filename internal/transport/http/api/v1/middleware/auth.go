package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/example/auth-service/internal/usecase"
	res "github.com/example/auth-service/pkg/http"
)

type AuthMiddleware struct {
	signer  usecase.JWTSigner
	service usecase.Service
}

func NewAuthMiddleware(signer usecase.JWTSigner, services ...usecase.Service) *AuthMiddleware {
	m := &AuthMiddleware{signer: signer}
	if len(services) > 0 {
		m.service = services[0]
	}
	return m
}

func (m *AuthMiddleware) Handler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authz := c.Request().Header.Get(echo.HeaderAuthorization)
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			return res.ErrorJSON(c, http.StatusUnauthorized, "unauthorized", "missing token", requestIDFromCtx(c), nil)
		}
		tok, claims, err := m.signer.Parse(parts[1])
		if err != nil || tok == nil || !tok.Valid {
			return res.ErrorJSON(c, http.StatusUnauthorized, "unauthorized", "invalid token", requestIDFromCtx(c), nil)
		}
		if m.service != nil {
			if _, e := m.service.VerifyToken(c.Request().Context(), requestIDFromCtx(c), parts[1]); e != nil {
				return res.ErrorJSON(c, 401, "unauthorized", "revoked session", requestIDFromCtx(c), nil)
			}
		}
		sub, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)
		if sub == "" {
			return res.ErrorJSON(c, http.StatusUnauthorized, "unauthorized", "subject missing", requestIDFromCtx(c), nil)
		}
		c.Set("user_id", sub)
		c.Set("email", email)
		return next(c)
	}
}

func requestIDFromCtx(c echo.Context) string {
	if reqID := c.Response().Header().Get(echo.HeaderXRequestID); reqID != "" {
		return reqID
	}
	return c.Request().Header.Get(echo.HeaderXRequestID)
}
