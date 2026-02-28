package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	nats "github.com/nats-io/nats.go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/example/auth-service/config"
	httpadapter "github.com/example/auth-service/internal/adapters/http"
	apiv1 "github.com/example/auth-service/internal/adapters/http/api/v1"
	handlers "github.com/example/auth-service/internal/adapters/http/api/v1/handlers"
	authmw "github.com/example/auth-service/internal/adapters/http/middleware"
	natsadapter "github.com/example/auth-service/internal/adapters/nats"
	repo "github.com/example/auth-service/internal/adapters/postgres"
	taraclient "github.com/example/auth-service/internal/adapters/tarantool"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	pkglog "github.com/example/auth-service/pkg/log"
)

type App struct {
	cfg      *config.Config
	logger   pkglog.Logger
	db       *gorm.DB
	natsConn *nats.Conn
	echo     *echo.Echo
}

func New(ctx context.Context) (*App, error) {
	cfg := config.MustLoad()
	logger := pkglog.New(cfg.AppEnv)

	db, err := gorm.Open(postgres.Open(buildDSN(cfg)), &gorm.Config{
		Logger:         loggerForGorm(cfg),
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
	})
	if err != nil {
		return nil, err
	}
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&domain.AuthUser{}, &domain.AuthIdentity{}, &domain.RefreshToken{}); err != nil {
		return nil, err
	}

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		log.Printf("nats connect failed: %v", err)
	}

	userRepo := repo.NewAuthUserRepository(db)
	identityRepo := repo.NewAuthIdentityRepository(db)
	refreshRepo := repo.NewRefreshTokenRepository(db)
	tarantoool := taraclient.NewHTTPClient(cfg.TarantoolSignupURL, 5*time.Second)
	var userClient natsadapter.UserClient
	var rbacClient natsadapter.RBACClient
	if nc != nil {
		userClient = natsadapter.NewUserClient(nc, cfg.NATSUserCreateSubject)
		rbacClient = natsadapter.NewRBACClient(nc, cfg.NATSAssignRoleSubject, cfg.NATSCheckRoleSubject)
	}

	signer, err := usecase.NewJWTSigner(cfg)
	if err != nil {
		return nil, err
	}

	service := usecase.NewAuthService(cfg, logger, userRepo, identityRepo, refreshRepo, tarantoool, userClient, rbacClient, signer)
	handler := handlers.NewAuthHandler(service)
	authMW := authmw.NewAuthMiddleware(signer)
	router := httpadapter.NewRouter(cfg, apiv1.NewRouter(handler, authMW.Handler))

	if nc != nil {
		verifyHandler := natsadapter.NewVerifyHandler(signer)
		_ = verifyHandler.Subscribe(nc, cfg.NATSVerifySubject, cfg.AppName)
	}

	e := echo.New()
	router.Setup(e)

	return &App{cfg: cfg, logger: logger, db: db, natsConn: nc, echo: e}, nil
}

func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.echo.Shutdown(shutdownCtx)
	}()
	go func() {
		errCh <- a.echo.Start(fmt.Sprintf("%s:%s", a.cfg.HTTPHost, a.cfg.HTTPPort))
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (a *App) Close() {
	if a.natsConn != nil {
		_ = a.natsConn.Drain()
	}
	if a.db != nil {
		if sqlDB, err := a.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
}

func buildDSN(cfg *config.Config) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)
}

func loggerForGorm(cfg *config.Config) logger.Interface {
	level := logger.Silent
	switch cfg.AppEnv {
	case "local":
		level = logger.Info
	default:
		level = logger.Warn
	}
	return logger.Default.LogMode(level)
}
