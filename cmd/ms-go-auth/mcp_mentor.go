package main

import (
	"net/url"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/infrastructure/httpclient"
	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	repo "github.com/example/auth-service/internal/infrastructure/persistence/postgres"
	"github.com/example/auth-service/internal/tokenverify"
	api "github.com/example/auth-service/internal/transport/http/api/v1/handlers"
	privatehttp "github.com/example/auth-service/internal/transport/http/private"
	"github.com/example/auth-service/internal/usecase"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	nats "github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

// Validate enabled-only configuration before opening a database, applying any
// legacy startup migration, connecting a broker or mounting routes.
func validateMCPMentorConfig(cfg *config.Config) error {
	if cfg == nil {
		return domain.ErrMCPMentorUnavailable
	}
	if !cfg.MCPMentorEnabled {
		if cfg.MCPMentorOffersEnabled || cfg.MCPMentorWorkspaceReadEnabled || cfg.MCPMentorSkillDraftEnabled {
			return domain.ErrMCPMentorUnavailable
		}
		return nil
	}
	if cfg.MCPMentorIssuer == cfg.JWTIssuer || (cfg.MCPStudentEnabled && cfg.MCPMentorIssuer == cfg.MCPIssuerURI) {
		return domain.ErrMCPMentorUnavailable
	}
	if cfg.DBMigrateOnStart || cfg.HTTPBasePath != "/api/v1" || cfg.MCPMentorAccessTTL < time.Second || cfg.MCPMentorAccessTTL > 5*time.Minute || cfg.MCPMentorConsentTTL < cfg.MCPMentorAccessTTL || cfg.MCPMentorConsentTTL > 24*time.Hour || !privatehttp.ValidMCPPersonaCapability(cfg.MCPAdapterVerifyCapability) || cfg.MCPMentorApprovalToken == cfg.MCPAdapterVerifyCapability || (cfg.MCPStudentEnabled && cfg.MCPResourceURI != cfg.MCPMentorResource) {
		return domain.ErrMCPMentorUnavailable
	}
	if _, err := usecase.NewMCPMentorTokens(cfg.MCPMentorIssuer, cfg.MCPMentorResource, cfg.MCPMentorPrivateKey, cfg.MCPMentorPublicKey); err != nil {
		return err
	}
	mentorKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.MCPMentorPublicKey))
	if err != nil {
		return domain.ErrMCPMentorUnavailable
	}
	if webKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.JWTPublicKey)); err == nil && webKey.N.Cmp(mentorKey.N) == 0 {
		return domain.ErrMCPMentorUnavailable
	}
	for _, legacy := range []string{cfg.MentorRolePublicKey, cfg.MentorLookupPublicKey} {
		if key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(legacy)); err == nil && key.N.Cmp(mentorKey.N) == 0 {
			return domain.ErrMCPMentorUnavailable
		}
	}
	decisionKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.MCPMentorRBACPublicKey))
	if err != nil || decisionKey.N.BitLen() < 2048 || decisionKey.N.BitLen() > 8192 || decisionKey.N.Cmp(mentorKey.N) == 0 {
		return domain.ErrMCPMentorUnavailable
	}
	if _, err := httpclient.NewMCPMentorApprovalClient(cfg.MCPMentorApprovalURL, cfg.MCPMentorApprovalToken, cfg.MCPMentorApprovalCAPEM); err != nil {
		return err
	}
	ui, err := url.Parse(cfg.MCPMentorConsentUI)
	if err != nil || ui.Scheme != "https" || ui.Hostname() == "" || ui.Path != "/mentor/mcp/consent" || ui.RawPath != "" || ui.RawQuery != "" || ui.ForceQuery || ui.User != nil || ui.Fragment != "" || ui.Opaque != "" || ui.String() != cfg.MCPMentorConsentUI {
		return domain.ErrMCPMentorUnavailable
	}
	return nil
}

func enableMCPMentorAccess(e *echo.Echo, cfg *config.Config, db *gorm.DB, nc *nats.Conn, parser tokenverify.Parser) (privatehttp.MCPMentorAccessVerifier, error) {
	if e == nil || cfg == nil || db == nil || nc == nil || parser == nil || !cfg.MCPMentorEnabled || cfg.HTTPBasePath != "/api/v1" || cfg.DBMigrateOnStart || cfg.MCPMentorAccessTTL < time.Second || cfg.MCPMentorAccessTTL > 5*time.Minute || cfg.MCPMentorConsentTTL < cfg.MCPMentorAccessTTL || cfg.MCPMentorConsentTTL > 24*time.Hour || cfg.MCPMentorApprovalToken == cfg.MCPAdapterVerifyCapability || (cfg.MCPStudentEnabled && cfg.MCPMentorResource != cfg.MCPResourceURI) {
		return nil, domain.ErrMCPMentorUnavailable
	}
	for _, table := range []string{"auth_mcp_mentor_client", "auth_mcp_mentor_consent", "auth_mcp_mentor_code"} {
		if !db.Migrator().HasTable(table) {
			return nil, domain.ErrMCPMentorUnavailable
		}
	}
	tokens, err := usecase.NewMCPMentorTokens(cfg.MCPMentorIssuer, cfg.MCPMentorResource, cfg.MCPMentorPrivateKey, cfg.MCPMentorPublicKey)
	if err != nil {
		return nil, err
	}
	rbac, err := natsadapter.NewMCPMentorRBACClient(nc, cfg.MCPMentorRBACPublicKey)
	if err != nil {
		return nil, err
	}
	owner, err := httpclient.NewMCPMentorApprovalClient(cfg.MCPMentorApprovalURL, cfg.MCPMentorApprovalToken, cfg.MCPMentorApprovalCAPEM)
	if err != nil {
		return nil, err
	}
	sessionReader, err := repo.NewMentorSessionReader(db)
	if err != nil {
		return nil, err
	}
	sessions, err := usecase.NewMentorLiveSessionVerifier(parser, sessionReader)
	if err != nil {
		return nil, err
	}
	oauth := &usecase.MCPMentorOAuth{Store: repo.NewMCPMentorStore(db), Tokens: tokens, Authority: usecase.MCPMentorLiveAuthority{Tokens: tokens, RBAC: rbac, Owner: owner}, Resource: cfg.MCPMentorResource, AccessTTL: cfg.MCPMentorAccessTTL, ConsentTTL: cfg.MCPMentorConsentTTL, OffersEnabled: cfg.MCPMentorOffersEnabled, WorkspaceReadEnabled: cfg.MCPMentorWorkspaceReadEnabled, SkillDraftEnabled: cfg.MCPMentorSkillDraftEnabled}
	handler := api.MCPMentorHandler{OAuth: oauth, Sessions: sessions, Resource: cfg.MCPMentorResource, ConsentUI: cfg.MCPMentorConsentUI}
	if err = handler.Validate(); err != nil {
		return nil, err
	}
	metadata, discovery, err := mcpMentorMetadata(cfg.MCPMentorIssuer, cfg.MCPMentorOffersEnabled, cfg.MCPMentorWorkspaceReadEnabled, cfg.MCPMentorSkillDraftEnabled)
	if err != nil || discovery != "/.well-known/oauth-authorization-server/mentor" {
		return nil, domain.ErrMCPMentorUnavailable
	}
	group := e.Group(cfg.HTTPBasePath + "/auth/mcp/mentor")
	group.GET("/authorize", handler.Authorize)
	group.GET("/consent", handler.Consent)
	group.POST("/consent", handler.Consent)
	group.POST("/token", handler.Token)
	group.POST("/revoke", handler.Revoke)
	e.GET(discovery, func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.JSON(200, metadata)
	})
	return oauth, nil
}

func mcpMentorMetadata(issuerURI string, offersEnabled, workspaceReadEnabled, skillDraftEnabled bool) (*usecase.MCPExternalASMetadata, string, error) {
	issuer, err := url.Parse(issuerURI)
	if err != nil || issuer.Scheme != "https" || issuer.Path != "/mentor" {
		return nil, "", domain.ErrMCPMentorUnavailable
	}
	origin := issuer.Scheme + "://" + issuer.Host
	scopes := []string{domain.MCPMentorScope}
	if offersEnabled {
		scopes = append(scopes, domain.MCPMentorOffersScope)
	}
	if workspaceReadEnabled {
		scopes = append(scopes, domain.MCPMentorWorkspaceReadScopes()...)
	}
	if skillDraftEnabled {
		scopes = append(scopes, domain.MCPMentorSkillDraftScope)
	}
	return usecase.BuildMCPExternalASMetadata(usecase.MCPExternalASMetadataConfig{PublicationApproved: true, Issuer: issuerURI, AuthorizationEndpoint: origin + "/api/auth/v1/auth/mcp/mentor/authorize", TokenEndpoint: origin + "/api/auth/v1/auth/mcp/mentor/token", SupportedStudentScopes: scopes})
}
