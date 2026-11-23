package main

import (
	"github.com/example/auth-service/config"
	private "github.com/example/auth-service/internal/transport/http/private"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotificationRecipientCompositionDefaultOffAndPurposeMount(t *testing.T) {
	e := echo.New()
	if err := mountNotificationRecipient(&config.Config{}, nil, e, nil); err != nil || len(e.Routes()) != 0 {
		t.Fatal("disabled capability mounted", err)
	}
	if err := mountNotificationRecipient(&config.Config{NotificationRecipientEnabled: true}, &gorm.DB{}, e, nil); err == nil || len(e.Routes()) != 0 {
		t.Fatal("empty credential mounted")
	}
	cfg := &config.Config{NotificationRecipientEnabled: true, NotificationRecipientToken: strings.Repeat("n", 40)}
	secure := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) })}
	if err := mountNotificationRecipient(cfg, &gorm.DB{}, e, secure); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []http.Handler{e, secure.Handler} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", private.NotificationRecipientPath, nil))
		if w.Code != 405 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("exact purpose route absent: %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	secure.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/unrelated", nil))
	if w.Code != 418 {
		t.Fatal("existing HTTPS route changed")
	}
}
