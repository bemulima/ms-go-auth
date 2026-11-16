package main

import (
	"errors"
	"time"

	"github.com/example/auth-service/config"
	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	repo "github.com/example/auth-service/internal/infrastructure/persistence/postgres"
	api "github.com/example/auth-service/internal/transport/http/api/v1/handlers"
	privatehttp "github.com/example/auth-service/internal/transport/http/private"
	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
	nats "github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

// enableMCPStudentAccess is deliberately opt-in. Do not attach frontend JWT
// verification or generic RBAC role ALLOW as an OAuth access-token fallback.
func enableMCPStudentAccess(e *echo.Echo, cfg *config.Config, db *gorm.DB, nc *nats.Conn, studentAuth echo.MiddlewareFunc) error {
	if e == nil || cfg == nil || db == nil || nc == nil || !cfg.MCPStudentEnabled ||
		studentAuth == nil ||
		cfg.MCPResourceURI == "" || cfg.MCPIssuerURI == "" ||
		cfg.JWTPrivateKey == "" || cfg.JWTPublicKey == "" ||
		cfg.RBACMCPRoleDecisionPublicKey == "" || cfg.RBACMCPScopeDecisionPublicKey == "" ||
		cfg.MCPAccessTTL <= 0 || cfg.MCPAccessTTL > 5*time.Minute {
		return errors.New("MCP external authorization prerequisites unavailable")
	}
	if !db.Migrator().HasTable("auth_mcp_client") || !db.Migrator().HasTable("auth_mcp_consent") ||
		!db.Migrator().HasTable("auth_mcp_authorization_code") {
		return errors.New("MCP external authorization schema unavailable")
	}
	roleSigner, err := usecase.NewMCPStudentRoleProofSigner(cfg.JWTIssuer, cfg.JWTPrivateKey, cfg.JWTPublicKey)
	if err != nil || roleSigner == nil {
		return errors.New("MCP Auth-to-RBAC Student role signer unavailable")
	}
	scopeSigner, err := usecase.NewMCPStudentScopeProofSigner(cfg.JWTIssuer, cfg.JWTPrivateKey, cfg.JWTPublicKey)
	if err != nil || scopeSigner == nil {
		return errors.New("MCP Auth-to-RBAC Student scope signer unavailable")
	}
	tokens, err := usecase.NewMCPExternalAccessJWTAuthority(cfg.MCPIssuerURI, cfg.MCPResourceURI, cfg.JWTPrivateKey, cfg.JWTPublicKey)
	if err != nil {
		return errors.New("MCP external JWT issuer unavailable")
	}
	composer := &usecase.MCPExternalGrantComposer{
		Reader:               repo.NewMCPExternalAuthGrantRepository(db),
		RoleProofSigner:      roleSigner,
		RoleDecisions:        natsadapter.NewMCPStudentRoleClient(nc, cfg.RBACMCPRoleDecisionPublicKey),
		ScopeProofSigner:     scopeSigner,
		ScopeDecisions:       natsadapter.NewMCPStudentScopeClient(nc, cfg.RBACMCPScopeDecisionPublicKey),
		AllowedStudentScopes: []string{"courses:read"},
	}
	verifier := usecase.MCPExternalAccessVerification{Tokens: tokens, Grants: composer}
	if err := privatehttp.RegisterMCPAccess(e.Group("/internal"), verifier, cfg.MCPAdapterVerifyCapability, cfg.MCPResourceURI); err != nil {
		return errors.New("MCP issuer-to-adapter verification route unavailable")
	}
	codeRepo := repo.NewMCPExternalCodeRepository(db)
	policy := usecase.MCPExternalPolicy{ResourceURI: cfg.MCPResourceURI, AllowedStudentScopes: []string{"courses:read"}}
	authorize := usecase.MCPExternalAuthorizeUsecase{
		Clients: repo.NewMCPExternalClientConsentRepository(db),
		Grants:  composer,
		Codes:   usecase.MCPExternalCodeUsecase{Codes: codeRepo, TTL: 5 * time.Minute},
		Policy:  policy,
	}
	exchange := usecase.MCPExternalTokenExchangeUsecase{
		Codes: codeRepo, Grants: composer,
		Policy: usecase.MCPExternalTokenPolicy{
			Issuer: cfg.MCPIssuerURI, ResourceURI: cfg.MCPResourceURI,
			AllowedStudentScopes: []string{"courses:read"}, AccessTTL: cfg.MCPAccessTTL,
		},
	}
	handler := api.MCPExternalOAuthHandler{
		Codes: authorize, Tokens: exchange, Signer: tokens,
		Revoker: repo.NewMCPExternalConsentRevoker(db), Resource: cfg.MCPResourceURI,
	}
	group := e.Group(cfg.HTTPBasePath + "/auth/mcp")
	if cfg.MCPBrowserEnabled {
		if cfg.HTTPBasePath != "/api/v1" {
			return errors.New("MCP browser issuer requires canonical Gateway Auth path")
		}
		handler.ConsentUIURI = cfg.MCPConsentUIURI
		if err := handler.ValidateBrowserUI(); err != nil {
			return err
		}
		metadata, discoveryPath, err := usecase.BuildMCPExternalASMetadata(usecase.MCPExternalASMetadataConfig{
			PublicationApproved:    true,
			Issuer:                 cfg.MCPIssuerURI,
			AuthorizationEndpoint:  cfg.MCPIssuerURI + "/api/auth/v1/auth/mcp/authorize",
			TokenEndpoint:          cfg.MCPIssuerURI + "/api/auth/v1/auth/mcp/token",
			SupportedStudentScopes: []string{"courses:read"},
		})
		if err != nil || discoveryPath != "/.well-known/oauth-authorization-server" {
			return errors.New("MCP authorization-server discovery prerequisites unavailable")
		}
		group.GET("/authorize", handler.StartBrowserAuthorization)
		e.GET(discoveryPath, func(c echo.Context) error {
			c.Response().Header().Set("Cache-Control", "no-store")
			return c.JSON(200, metadata)
		})
	}
	group.POST("/authorization/complete", handler.CompleteAuthorization, studentAuth)
	group.POST("/token", handler.ExchangeToken)
	group.POST("/consent/revoke", handler.RevokeConsent, studentAuth)
	// Browser GET and metadata remain disabled unless explicitly configured;
	// all codes and OAuth access still require Auth-owned consent and fresh RBAC.
	return nil
}
