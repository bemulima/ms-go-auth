package v1

import (
	"github.com/labstack/echo/v4"

	"github.com/example/auth-service/internal/adapters/http/api/v1/handlers"
)

type Router struct {
	handlers *handlers.AuthHandler
	authMW   echo.MiddlewareFunc
}

func NewRouter(h *handlers.AuthHandler, authMW echo.MiddlewareFunc) *Router {
	return &Router{handlers: h, authMW: authMW}
}

func (r *Router) Register(g *echo.Group) {
	auth := g.Group("/auth")
	auth.POST("/signup/start", r.handlers.SignupStart)
	auth.POST("/signup/verify", r.handlers.SignupVerify)
	auth.POST("/signin", r.handlers.SignIn)
	auth.POST("/refresh", r.handlers.Refresh)
	auth.POST("/oauth/:provider/callback", r.handlers.OAuthCallback)
	auth.POST("/password/reset/start", r.handlers.PasswordResetStart)
	auth.POST("/password/reset/finish", r.handlers.PasswordResetFinish)
	auth.POST("/verify", r.handlers.VerifyToken)
	auth.POST("/email/change/verify", r.handlers.EmailChangeVerify)

	protected := auth.Group("", r.authMW)
	protected.POST("/email/change/start", r.handlers.EmailChangeStart)
	protected.POST("/password/change", r.handlers.ChangePassword)
}
