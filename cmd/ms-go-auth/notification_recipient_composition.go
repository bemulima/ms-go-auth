package main

import (
	"errors"
	"github.com/example/auth-service/config"
	repo "github.com/example/auth-service/internal/infrastructure/persistence/postgres"
	private "github.com/example/auth-service/internal/transport/http/private"
	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"net/http"
	"time"
)

// The capability is absent by default. Direct consumers must use a pinned
// HTTPS origin; the ordinary Echo listener requires trusted TLS termination.
// An enabled Mentor HTTPS listener also exposes this exact purpose route.
func mountNotificationRecipient(cfg *config.Config, db *gorm.DB, e *echo.Echo, secure *http.Server) error {
	if cfg == nil {
		return errors.New("notification recipient configuration unavailable")
	}
	if !cfg.NotificationRecipientEnabled {
		return nil
	}
	if db == nil || e == nil {
		return errors.New("notification recipient dependencies unavailable")
	}
	if secure != nil && secure.Handler == nil {
		return errors.New("HTTPS handler unavailable")
	}
	h, err := private.NewNotificationRecipientHandler(cfg.NotificationRecipientToken, usecase.NotificationRecipientService{Reader: repo.NewNotificationRecipientReader(db), Now: time.Now})
	if err != nil {
		return err
	}
	e.Any(private.NotificationRecipientPath, echo.WrapHandler(h))
	if secure != nil {
		prior := secure.Handler
		mux := http.NewServeMux()
		mux.Handle(private.NotificationRecipientPath, h)
		mux.Handle("/", prior)
		secure.Handler = mux
	}
	return nil
}
