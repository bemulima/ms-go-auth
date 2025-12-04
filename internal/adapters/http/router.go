package http

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/example/auth-service/config"
	v1 "github.com/example/auth-service/internal/adapters/http/api/v1"
	internalhttp "github.com/example/auth-service/internal/adapters/http/internal"
)

type Router struct {
	cfg       *config.Config
	apiRouter *v1.Router
}

func NewRouter(cfg *config.Config, apiRouter *v1.Router) *Router {
	return &Router{cfg: cfg, apiRouter: apiRouter}
}

func (r *Router) Setup(e *echo.Echo) {
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())

	internalhttp.Register(e)
	apiGroup := e.Group(r.cfg.HTTPBasePath)
	r.apiRouter.Register(apiGroup)
}
