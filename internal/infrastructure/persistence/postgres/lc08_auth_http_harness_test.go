package repo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/transport/http/api/v1/handlers"
	"github.com/example/auth-service/internal/usecase"
	pkglog "github.com/example/auth-service/pkg/log"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type lc08HarnessUsers struct {
	domain.AuthUserRepository
	domain.SignupCompletionRepository
}

func (lc08HarnessUsers) SignupPrincipalPending(context.Context, string) (bool, error) {
	return false, nil
}
func (lc08HarnessUsers) FindSignupCompletionByPrincipal(context.Context, string) (*domain.SignupCompletion, error) {
	return nil, domain.ErrNotFound
}

type lc08HarnessRBAC struct{ roles map[string]string }

func lc08Hash(jti string) string { return "rt:" + jti }
func (r lc08HarnessRBAC) AssignRole(context.Context, string, string) error {
	return errors.New("test RBAC is read-only")
}
func (r lc08HarnessRBAC) CheckRole(_ context.Context, id, role string) (bool, error) {
	return r.roles[id] == role, nil
}

// Test-only process for the owner's bounded isolated cross-process integration.
// It exposes real HTTP handlers/usecase/Postgres; RBAC and signup readiness are
// explicit fixtures, not evidence about deployed RBAC or signup.
func TestLC08AuthHTTPHarness(t *testing.T) {
	if os.Getenv("LC08_AUTH_HTTP_HARNESS") != "1" {
		t.Skip("explicit isolated harness opt-in required")
	}
	dsn := os.Getenv("LC08_AUTH_ATOMIC_TEST_DSN")
	if !strings.Contains(dsn, "host=/var/run/postgresql") || !strings.Contains(dsn, "dbname=lc08_auth_atomic_20261028_test") {
		t.Fatal("unsafe database DSN")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	var name string
	var socket bool
	if err = db.Raw("SELECT current_database(), inet_server_addr() IS NULL").Row().Scan(&name, &socket); err != nil || name != "lc08_auth_atomic_20261028_test" || !socket {
		t.Fatal("unsafe DB")
	}
	raw, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: hex.EncodeToString(key), JWTIssuer: "lc08-test", JWTAudience: "frontend", AccessTTL: time.Minute, RefreshTTL: time.Hour, DefaultRole: "student"}
	signer, err := usecase.NewJWTSigner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	password := "isolated-test-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"student", "student_pro", "teacher", "moderator", "admin"} {
		id := t16RepoUUID(t)
		email := "lc08-" + strings.ReplaceAll(id, "-", "") + "@isolated.invalid"
		if err = db.Exec("INSERT INTO auth_user(id,email,password_hash) VALUES (?,?,?)", id, email, string(hash)).Error; err != nil {
			t.Fatal(err)
		}
		roles[id] = role
	}
	users := lc08HarnessUsers{AuthUserRepository: NewAuthUserRepository(db)}
	svc := usecase.NewAuthService(cfg, pkglog.New("test"), users, nil, nil, nil, NewRefreshTokenRepository(db), nil, nil, lc08HarnessRBAC{roles: roles}, signer)
	h := handlers.NewAuthHandler(svc)
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.POST("/api/auth/v1/auth/refresh", h.Refresh)
	e.POST("/api/auth/v1/auth/verify", h.VerifyToken)
	e.POST("/api/auth/v1/auth/revoke", h.RevokeRefresh)
	e.POST("/api/auth/v1/auth/signin", h.SignIn)
	e.POST("/api/v1/auth/refresh", h.Refresh)
	e.POST("/api/v1/auth/verify", h.VerifyToken)
	e.POST("/api/v1/auth/revoke", h.RevokeRefresh)
	e.POST("/api/v1/auth/signin", h.SignIn)
	// Fixture creates only test identities and sessions in the dedicated DB.
	e.POST("/__fixture/session", func(c echo.Context) error {
		var x struct {
			Role           string `json:"role"`
			Expired        bool   `json:"expired"`
			RefreshExpired bool   `json:"refresh_expired"`
		}
		if err := c.Bind(&x); err != nil {
			return c.NoContent(400)
		}
		id := ""
		for candidate, role := range roles {
			if role == x.Role {
				id = candidate
				break
			}
		}
		if id == "" {
			return c.NoContent(400)
		}
		jti, err := usecase.GenerateJTI()
		if err != nil {
			return c.String(500, "fixture jti error")
		}
		refreshTTL := time.Hour
		if x.RefreshExpired {
			refreshTTL = -time.Hour
		}
		tokens := &domain.RefreshToken{UserID: id, RefreshTokenHash: lc08Hash(jti), ExpiresAt: time.Now().Add(refreshTTL)}
		if err = NewRefreshTokenRepository(db).Create(c.Request().Context(), tokens); err != nil {
			if errors.Is(err, context.Canceled) {
				return c.String(500, "fixture insert context canceled")
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return c.String(500, "fixture insert deadline exceeded")
			}
			var postgresError *pgconn.PgError
			if errors.As(err, &postgresError) {
				return c.String(500, "fixture insert SQLSTATE "+postgresError.Code)
			}
			return c.String(500, "fixture session insert unknown")
		}
		ttl := time.Minute
		if x.Expired {
			ttl = -time.Hour
		}
		access, err := signer.SignAccessToken(id, map[string]interface{}{"role": x.Role, "sid": jti}, ttl)
		if err != nil {
			return c.String(500, "fixture access signing error")
		}
		refresh, err := signer.SignRefreshToken(id, jti, refreshTTL)
		if err != nil {
			return c.String(500, "fixture refresh signing error")
		}
		user, err := users.FindByID(c.Request().Context(), id)
		if err != nil {
			return c.String(500, "fixture user read error")
		}
		return c.JSON(200, map[string]any{"user_id": id, "email": user.Email, "access_token": access, "refresh_token": refresh})
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:18555")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e}
	go func() { _ = srv.Serve(ln) }()
	t.Log("isolated Auth handler ready on 127.0.0.1:18555; RBAC mocked")
	duration := 3 * time.Minute
	if configured := os.Getenv("LC08_AUTH_HTTP_SECONDS"); configured != "" {
		seconds, err := strconv.Atoi(configured)
		if err != nil || seconds < 30 || seconds > 900 {
			t.Fatal("invalid bounded harness duration")
		}
		duration = time.Duration(seconds) * time.Second
	}
	<-time.After(duration)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
