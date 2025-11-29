package http

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/adapter/http/handlers"
)

type Router struct {
	cfg      *config.Config
	handlers *handlers.AuthHandler
	authMW   echo.MiddlewareFunc
}

func NewRouter(cfg *config.Config, h *handlers.AuthHandler, authMW echo.MiddlewareFunc) *Router {
	return &Router{cfg: cfg, handlers: h, authMW: authMW}
}

func (r *Router) Setup(e *echo.Echo) {
	base := r.cfg.HTTPBasePath
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	auth := e.Group(base + "/auth")
	auth.POST("/signup/start", r.handlers.SignupStart)
	auth.POST("/signup/verify", r.handlers.SignupVerify)
	auth.POST("/signin", r.handlers.SignIn)
	auth.POST("/refresh", r.handlers.Refresh)
	auth.POST("/oauth/:provider/callback", r.handlers.OAuthCallback)
	auth.POST("/password/reset/start", r.handlers.PasswordResetStart)
	auth.POST("/password/reset/finish", r.handlers.PasswordResetFinish)
	auth.POST("/email/change/verify", r.handlers.EmailChangeVerify)

	protected := e.Group(base+"/auth", r.authMW)
	protected.POST("/email/change/start", r.handlers.EmailChangeStart)
}
