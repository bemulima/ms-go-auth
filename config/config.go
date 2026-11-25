package config

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
)

type Config struct {
	NotificationRecipientEnabled bool   `env:"AUTH_NOTIFICATION_RECIPIENT_ENABLED" envDefault:"false"`
	NotificationRecipientToken   string `env:"AUTH_NOTIFICATION_RECIPIENT_TOKEN"`
	EmailCodeHMACKey             string `env:"AUTH_EMAIL_CODE_HMAC_KEY"`
	SMTPAddress                  string `env:"AUTH_SMTP_ADDRESS"`
	SMTPFrom                     string `env:"AUTH_SMTP_FROM" envDefault:"auth@example.test"`
	EmailOriginLimit             int    `env:"AUTH_EMAIL_ORIGIN_HOURLY_LIMIT" envDefault:"20"`
	AppName                      string `env:"AUTH_APP_NAME" envDefault:"auth-service"`
	AppEnv                       string `env:"AUTH_APP_ENV" envDefault:"local"`
	HTTPHost                     string `env:"AUTH_HTTP_HOST" envDefault:"0.0.0.0"`
	HTTPPort                     string `env:"AUTH_HTTP_PORT" envDefault:"8081"`
	HTTPBasePath                 string `env:"AUTH_HTTP_BASE_PATH" envDefault:"/api/v1"`

	MentorEnabled              bool   `env:"AUTH_MENTOR_ENABLED" envDefault:"false"`
	MentorHTTPSAddress         string `env:"AUTH_MENTOR_HTTPS_ADDR"`
	MentorTLSCertFile          string `env:"AUTH_MENTOR_TLS_CERT_FILE"`
	MentorTLSKeyFile           string `env:"AUTH_MENTOR_TLS_KEY_FILE"`
	MentorRolePrivateKey       string `env:"AUTH_MENTOR_ROLE_DECISION_PRIVATE_KEY"`
	MentorRolePublicKey        string `env:"AUTH_MENTOR_ROLE_DECISION_PUBLIC_KEY"`
	MentorLookupPrivateKey     string `env:"AUTH_MENTOR_OWNER_LOOKUP_PRIVATE_KEY"`
	MentorLookupPublicKey      string `env:"AUTH_MENTOR_OWNER_LOOKUP_PUBLIC_KEY"`
	MentorRBACReplyPublicKey   string `env:"AUTH_MENTOR_RBAC_REPLY_PUBLIC_KEY"`
	MentorIntentReplyPublicKey string `env:"AUTH_MENTOR_INTENT_REPLY_PUBLIC_KEY"`
	MentorNATSURL              string `env:"AUTH_MENTOR_NATS_URL"`
	MentorNATSCredentialsFile  string `env:"AUTH_MENTOR_NATS_CREDENTIALS_FILE"`
	MentorNATSCAFile           string `env:"AUTH_MENTOR_NATS_CA_FILE"`

	DBHost     string `env:"AUTH_DB_HOST" envDefault:"localhost"`
	DBPort     string `env:"AUTH_DB_PORT" envDefault:"5432"`
	DBUser     string `env:"AUTH_DB_USER" envDefault:"app"`
	DBPassword string `env:"AUTH_DB_PASSWORD" envDefault:"app_password"`
	DBName     string `env:"AUTH_DB_NAME" envDefault:"authdb"`
	DBSSLMode  string `env:"AUTH_DB_SSLMODE" envDefault:"disable"`
	// DBMigrateOnStart preserves the historical startup behavior by default.
	// Rollout environments can disable all schema-changing startup statements
	// and apply owner migrations explicitly before starting the service.
	DBMigrateOnStart bool `env:"AUTH_DB_MIGRATE_ON_START" envDefault:"true"`

	JWTSecret     string        `env:"AUTH_JWT_SECRET"`
	JWTPrivateKey string        `env:"AUTH_JWT_PRIVATE_KEY"`
	JWTPublicKey  string        `env:"AUTH_JWT_PUBLIC_KEY"`
	JWTAudience   string        `env:"AUTH_JWT_AUDIENCE" envDefault:"frontend"`
	JWTIssuer     string        `env:"AUTH_JWT_ISSUER" envDefault:"auth-service"`
	AccessTTL     time.Duration `env:"AUTH_JWT_ACCESS_TTL" envDefault:"15m"`
	RefreshTTL    time.Duration `env:"AUTH_JWT_REFRESH_TTL" envDefault:"720h"`

	RBACSignupPrivateKey            string `env:"AUTH_RBAC_SIGNUP_PRIVATE_KEY"`
	RBACPermissionDecisionPublicKey string `env:"AUTH_RBAC_PERMISSION_DECISION_PUBLIC_KEY"`

	// The external MCP issuer is opt-in and separate from frontend JWTs.
	MCPStudentEnabled bool `env:"AUTH_MCP_STUDENT_ENABLED" envDefault:"false"`
	// Mutation scopes are separately opt-in. Existing consent/client/RBAC
	// gates still apply per scope, even if this ceiling is widened.
	MCPWriteScopesEnabled bool `env:"AUTH_MCP_WRITE_SCOPES_ENABLED" envDefault:"false"`
	// Private graph and lesson scopes require separate operator opt-in.
	// This flag never creates client/consent/RBAC grants.
	MCPPrivateLearningReadScopesEnabled bool `env:"AUTH_MCP_PRIVATE_LEARNING_READ_SCOPES_ENABLED" envDefault:"false"`
	// Browser OAuth discovery is a separate opt-in until the first-party consent
	// UI and its exact Gateway entrypoints have been qualified end-to-end.
	MCPBrowserEnabled             bool          `env:"AUTH_MCP_BROWSER_ENABLED" envDefault:"false"`
	MCPConsentUIURI               string        `env:"AUTH_MCP_CONSENT_UI_URI"`
	MCPIssuerURI                  string        `env:"AUTH_MCP_ISSUER_URI"`
	MCPResourceURI                string        `env:"AUTH_MCP_RESOURCE_URI"`
	MCPAccessTTL                  time.Duration `env:"AUTH_MCP_ACCESS_TTL" envDefault:"5m"`
	MCPAdapterVerifyCapability    string        `env:"AUTH_MCP_ADAPTER_VERIFY_TOKEN"`
	RBACMCPRoleDecisionPublicKey  string        `env:"AUTH_RBAC_MCP_STUDENT_ROLE_DECISION_PUBLIC_KEY"`
	RBACMCPScopeDecisionPublicKey string        `env:"AUTH_RBAC_MCP_STUDENT_SCOPE_DECISION_PUBLIC_KEY"`
	// Mentor grants, signing keys and consent remain separate from Student.
	MCPMentorEnabled              bool          `env:"MCP_MENTOR_EXTERNAL_ENABLED" envDefault:"false"`
	MCPMentorSkillDraftEnabled    bool          `env:"MCP_MENTOR_SKILL_DRAFT_ENABLED" envDefault:"false"`
	MCPMentorWorkspaceReadEnabled bool          `env:"MCP_MENTOR_WORKSPACE_READ_ENABLED" envDefault:"false"`
	MCPMentorOffersEnabled        bool          `env:"MCP_MENTOR_OFFERS_ENABLED" envDefault:"false"`
	MCPMentorIssuer               string        `env:"MCP_MENTOR_ISSUER"`
	MCPMentorResource             string        `env:"MCP_MENTOR_RESOURCE_URI"`
	MCPMentorConsentUI            string        `env:"MCP_MENTOR_CONSENT_UI_URI"`
	MCPMentorPrivateKey           string        `env:"MCP_MENTOR_PRIVATE_KEY"`
	MCPMentorPublicKey            string        `env:"MCP_MENTOR_PUBLIC_KEY"`
	MCPMentorRBACPublicKey        string        `env:"MCP_MENTOR_RBAC_DECISION_PUBLIC_KEY"`
	MCPMentorApprovalURL          string        `env:"MCP_MENTOR_APPROVAL_URL"`
	MCPMentorApprovalToken        string        `env:"MCP_MENTOR_APPROVAL_TOKEN"`
	MCPMentorApprovalCAPEM        string        `env:"MCP_MENTOR_APPROVAL_CA_PEM"`
	MCPMentorAccessTTL            time.Duration `env:"MCP_MENTOR_ACCESS_TTL" envDefault:"5m"`
	MCPMentorConsentTTL           time.Duration `env:"MCP_MENTOR_CONSENT_TTL" envDefault:"24h"`

	NATSURL                    string `env:"NATS_URL" envDefault:"nats://localhost:4222"`
	NATSVerifySubject          string `env:"NATS_SUBJECT_VERIFY_JWT" envDefault:"auth.verifyJWT"`
	NATSUserCreateSubject      string `env:"NATS_SUBJECT_USER_CREATE" envDefault:"user.create-user"`
	NATSAssignRoleSubject      string `env:"NATS_SUBJECT_ASSIGN_ROLE" envDefault:"rbac.assign-role"`
	NATSCheckRoleSubject       string `env:"NATS_SUBJECT_CHECK_ROLE" envDefault:"rbac.checkRole"`
	NATSCheckPermissionSubject string `env:"NATS_SUBJECT_CHECK_PERMISSION" envDefault:"rbac.checkPermission"`

	TarantoolHost             string        `env:"TARANTOOL_HOST" envDefault:"localhost"`
	TarantoolPort             string        `env:"TARANTOOL_PORT" envDefault:"3301"`
	TarantoolUser             string        `env:"TARANTOOL_USER"`
	TarantoolPassword         string        `env:"TARANTOOL_PASSWORD"`
	TarantoolConnectTimeout   time.Duration `env:"TARANTOOL_CONNECT_TIMEOUT" envDefault:"5s"`
	TarantoolRequestTimeout   time.Duration `env:"TARANTOOL_REQUEST_TIMEOUT" envDefault:"3s"`
	VerificationSignupCodeTTL time.Duration `env:"AUTH_VERIFICATION_SIGNUP_CODE_TTL" envDefault:"5m"`
	VerificationSignupHardTTL time.Duration `env:"AUTH_VERIFICATION_SIGNUP_HARD_TTL" envDefault:"24h"`
	VerificationEmailCodeTTL  time.Duration `env:"AUTH_VERIFICATION_EMAIL_CODE_TTL" envDefault:"5m"`
	VerificationEmailHardTTL  time.Duration `env:"AUTH_VERIFICATION_EMAIL_HARD_TTL" envDefault:"24h"`

	DefaultRole string `env:"AUTH_DEFAULT_ROLE" envDefault:"student"`

	OAuthGoogleBoundaryURL  string `env:"AUTH_OAUTH_GOOGLE_BOUNDARY_URL"`
	OAuthGoogleClientID     string `env:"AUTH_OAUTH_GOOGLE_CLIENT_ID"`
	OAuthGoogleClientSecret string `env:"AUTH_OAUTH_GOOGLE_CLIENT_SECRET"`
	OAuthGoogleRedirectURL  string `env:"AUTH_OAUTH_GOOGLE_REDIRECT_URL"`

	OAuthGitHubBoundaryURL  string `env:"AUTH_OAUTH_GITHUB_BOUNDARY_URL"`
	OAuthGitHubClientID     string `env:"AUTH_OAUTH_GITHUB_CLIENT_ID"`
	OAuthGitHubClientSecret string `env:"AUTH_OAUTH_GITHUB_CLIENT_SECRET"`
	OAuthGitHubRedirectURL  string `env:"AUTH_OAUTH_GITHUB_REDIRECT_URL"`

	OAuthTransactionTTL time.Duration `env:"AUTH_OAUTH_TRANSACTION_TTL" envDefault:"10m"`
}

func Load() (*Config, error) {
	_ = godotenv.Load()
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	return cfg
}

// ValidateLocalOAuthBoundary prevents test provider routing in shared deployments.
func (c *Config) ValidateLocalOAuthBoundary() error {
	if c.OAuthGoogleBoundaryURL == "" && c.OAuthGitHubBoundaryURL == "" {
		return nil
	}
	if c.AppEnv != "test" || c.HTTPHost != "127.0.0.1" || c.DBHost != "127.0.0.1" || !strings.HasSuffix(c.DBName, "_test") || c.DBMigrateOnStart {
		return fmt.Errorf("local OAuth boundary requires loopback test runtime with owner-migrated test database")
	}
	return nil
}
