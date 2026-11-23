package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	nats "github.com/nats-io/nats.go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	mailadapter "github.com/example/auth-service/internal/infrastructure/mail"
	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	oauthprovider "github.com/example/auth-service/internal/infrastructure/oauth"
	repo "github.com/example/auth-service/internal/infrastructure/persistence/postgres"
	taraclient "github.com/example/auth-service/internal/infrastructure/persistence/tarantool"
	httpadapter "github.com/example/auth-service/internal/transport/http"
	apiv1 "github.com/example/auth-service/internal/transport/http/api/v1"
	handlers "github.com/example/auth-service/internal/transport/http/api/v1/handlers"
	authmw "github.com/example/auth-service/internal/transport/http/api/v1/middleware"
	"github.com/example/auth-service/internal/usecase"
	verification "github.com/example/auth-service/internal/usecase/verification"
	pkglog "github.com/example/auth-service/pkg/log"
)

type App struct {
	cfg               *config.Config
	logger            pkglog.Logger
	db                *gorm.DB
	natsConn          *nats.Conn
	echo              *echo.Echo
	verificationStore *taraclient.Client
	mentorHTTPS       *http.Server
	mentorBroker      *mentorRuntimeBroker
}

func New(ctx context.Context) (*App, error) {
	cfg := config.MustLoad()
	if err := cfg.ValidateLocalOAuthBoundary(); err != nil {
		return nil, err
	}
	mentorPrepared, err := prepareMentorRuntime(cfg, defaultMentorRuntimeLoaders())
	if err != nil {
		return nil, err
	}
	google := oauthprovider.NewGoogleOAuth2(cfg.OAuthGoogleClientID, cfg.OAuthGoogleClientSecret, cfg.OAuthGoogleRedirectURL)
	if cfg.OAuthGoogleBoundaryURL != "" {
		if err := google.UseLocalBoundary(cfg.OAuthGoogleBoundaryURL); err != nil {
			return nil, err
		}
	}
	github := oauthprovider.NewGitHubOAuth2(cfg.OAuthGitHubClientID, cfg.OAuthGitHubClientSecret, cfg.OAuthGitHubRedirectURL)
	if cfg.OAuthGitHubBoundaryURL != "" {
		if err := github.UseLocalBoundary(cfg.OAuthGitHubBoundaryURL); err != nil {
			return nil, err
		}
	}
	logger := pkglog.New(cfg.AppEnv)

	db, err := gorm.Open(postgres.Open(buildDSN(cfg)), &gorm.Config{
		Logger:         loggerForGorm(cfg),
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
	})
	if err != nil {
		return nil, err
	}
	if err := applyDatabaseMigrations(db, cfg); err != nil {
		return nil, err
	}

	nc, err := connectNATSWithRetry(cfg, logger)
	if err != nil {
		return nil, err
	}

	userRepo := repo.NewAuthUserRepository(db)
	identityRepo := repo.NewAuthIdentityRepository(db)
	oauthTxRepo := repo.NewOAuthTransactionRepository(db)
	refreshRepo := repo.NewRefreshTokenRepository(db)
	connectCtx, cancel := context.WithTimeout(ctx, cfg.TarantoolConnectTimeout)
	verificationStore, err := taraclient.Connect(connectCtx, taraclient.ConnectionConfig{Address: net.JoinHostPort(cfg.TarantoolHost, cfg.TarantoolPort), User: cfg.TarantoolUser, Password: cfg.TarantoolPassword, RequestTimeout: cfg.TarantoolRequestTimeout})
	cancel()
	if err != nil {
		nc.Close()
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
		return nil, err
	}
	initialized := false
	defer func() {
		if !initialized {
			_ = verificationStore.Close()
			nc.Close()
			if sqlDB, e := db.DB(); e == nil {
				_ = sqlDB.Close()
			}
		}
	}()
	tarantoool := verification.NewService(verificationStore, verification.Options{SignupCodeTTL: cfg.VerificationSignupCodeTTL, SignupHardTTL: cfg.VerificationSignupHardTTL, EmailCodeTTL: cfg.VerificationEmailCodeTTL, EmailHardTTL: cfg.VerificationEmailHardTTL})
	userClient := natsadapter.NewUserClient(nc, cfg.NATSUserCreateSubject)
	rbacClient, err := natsadapter.NewRBACClientWithSignupProof(nc, cfg.NATSAssignRoleSubject, cfg.NATSCheckRoleSubject, cfg.RBACSignupPrivateKey)
	if err != nil {
		return nil, err
	}

	signer, err := usecase.NewJWTSigner(cfg)
	if err != nil {
		return nil, err
	}
	var mentorHTTPS *http.Server
	var mentorBroker *mentorRuntimeBroker
	if mentorPrepared != nil {
		mentorBroker, err = connectMentorRuntimeBroker(ctx, mentorPrepared, dialMentorRuntimeBroker)
		if err != nil {
			return nil, ErrMentorRuntimeUnavailable
		}
		defer func() {
			if !initialized {
				mentorBroker.Close()
			}
		}()
		mentorHTTPS, err = newMentorHTTPSServer(mentorPrepared, MentorCompositionDependencies{DB: db, Parser: signer, Requester: mentorBroker})
		if err != nil {
			return nil, ErrMentorRuntimeUnavailable
		}
	}

	oauthRegistry := oauthprovider.NewRegistry(
		google,
		github,
	)
	service := usecase.NewAuthService(cfg, logger, userRepo, identityRepo, oauthTxRepo, oauthRegistry, refreshRepo, tarantoool, userClient, rbacClient, signer)
	if err := usecase.EnableEmailCodes(service, verificationStore, &mailadapter.SMTP{Address: cfg.SMTPAddress, From: cfg.SMTPFrom}, cfg.EmailCodeHMACKey, cfg.EmailOriginLimit); err != nil {
		return nil, err
	}
	permissionClient := natsadapter.NewRBACPermissionClient(nc, cfg.NATSCheckPermissionSubject, cfg.RBACPermissionDecisionPublicKey)
	reviewerIssuer, err := usecase.NewKnowledgeReviewerTokenIssuer(cfg.JWTIssuer, cfg.JWTPrivateKey, cfg.JWTPublicKey, permissionClient)
	if err != nil {
		return nil, err
	}
	handler := handlers.NewAuthHandler(service)
	if reviewerIssuer != nil {
		handler = handlers.NewAuthHandler(service, reviewerIssuer)
	}
	authMW := authmw.NewAuthMiddleware(signer, service)
	router := httpadapter.NewRouter(cfg, apiv1.NewRouter(handler, authMW.Handler))

	verifyHandler := natsadapter.NewVerifyHandler(signer, service)
	_ = verifyHandler.Subscribe(nc, cfg.NATSVerifySubject, cfg.AppName)

	e := echo.New()
	router.Setup(e)
	if err := mountNotificationRecipient(cfg, db, e, mentorHTTPS); err != nil {
		return nil, err
	}

	initialized = true
	return &App{cfg: cfg, logger: logger, db: db, natsConn: nc, echo: e, verificationStore: verificationStore, mentorHTTPS: mentorHTTPS, mentorBroker: mentorBroker}, nil
}

// applyDatabaseMigrations is intentionally a single gate around every
// schema-changing startup statement. The explicit owner migration helper can
// be used when AUTH_DB_MIGRATE_ON_START is false.
func applyDatabaseMigrations(db *gorm.DB, cfg *config.Config) error {
	if !cfg.DBMigrateOnStart {
		return nil
	}
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
		return err
	}
	if err := db.Exec(`
		ALTER TABLE IF EXISTS auth_user
			ALTER COLUMN password_hash DROP NOT NULL,
			ALTER COLUMN password_updated_at DROP NOT NULL
	`).Error; err != nil {
		return err
	}
	return db.AutoMigrate(&domain.AuthUser{}, &domain.AuthIdentity{}, &domain.RefreshToken{}, &domain.OAuthTransaction{}, &domain.SignupCompletion{})
}

func (a *App) Run(ctx context.Context) error {
	if a.mentorHTTPS != nil {
		return a.runMentorHTTPS(ctx)
	}
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

// The new authority is never mounted on plaintext Echo. Only the explicitly
// enabled branch supervises both listeners and the separate secure requester.
func (a *App) runMentorHTTPS(ctx context.Context) error {
	if ctx == nil || a.cfg == nil || a.echo == nil || a.mentorHTTPS == nil || a.mentorBroker == nil {
		return ErrMentorRuntimeUnavailable
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer a.mentorBroker.Close()
	a.mentorHTTPS.BaseContext = func(net.Listener) context.Context { return runCtx }
	servers := []mentorServerLifecycle{
		{start: func() error { return a.echo.Start(net.JoinHostPort(a.cfg.HTTPHost, a.cfg.HTTPPort)) }, shutdown: func(c context.Context) error { cancel(); return a.echo.Shutdown(c) }, close: a.echo.Close},
		{start: func() error { return a.mentorHTTPS.ListenAndServeTLS("", "") }, shutdown: func(c context.Context) error { cancel(); return a.mentorHTTPS.Shutdown(c) }, close: a.mentorHTTPS.Close},
	}
	return runMentorServers(runCtx, servers, a.mentorBroker.done)
}

func (a *App) Close() {
	if a.mentorHTTPS != nil {
		_ = a.mentorHTTPS.Close()
	}
	if a.mentorBroker != nil {
		a.mentorBroker.Close()
	}
	if a.verificationStore != nil {
		_ = a.verificationStore.Close()
	}
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

func connectNATSWithRetry(cfg *config.Config, logger pkglog.Logger) (*nats.Conn, error) {
	const (
		maxAttempts = 30
		retryDelay  = 2 * time.Second
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		conn, err := nats.Connect(cfg.NATSURL)
		if err == nil {
			return conn, nil
		}

		lastErr = err
		log.Printf("nats connect attempt %d/%d failed", attempt, maxAttempts)

		if attempt < maxAttempts {
			time.Sleep(retryDelay)
		}
	}

	logger.Error().Msg("nats connection failed after retries")
	_ = lastErr
	return nil, errors.New("nats connect failed after retries")
}

func loggerForGorm(cfg *config.Config) logger.Interface {
	// SQL statements may contain credentials. Parameterized queries omit bound
	// values even in failure diagnostics and local development logs.
	return logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{SlowThreshold: time.Second, LogLevel: logger.Warn, IgnoreRecordNotFoundError: true, ParameterizedQueries: true})
}
