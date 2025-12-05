package config

import (
	"log"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
)

type Config struct {
	AppName      string `env:"AUTH_APP_NAME" envDefault:"auth-service"`
	AppEnv       string `env:"AUTH_APP_ENV" envDefault:"local"`
	HTTPHost     string `env:"AUTH_HTTP_HOST" envDefault:"0.0.0.0"`
	HTTPPort     string `env:"AUTH_HTTP_PORT" envDefault:"8081"`
	HTTPBasePath string `env:"AUTH_HTTP_BASE_PATH" envDefault:"/api/v1"`

	DBHost     string `env:"AUTH_DB_HOST" envDefault:"localhost"`
	DBPort     string `env:"AUTH_DB_PORT" envDefault:"5432"`
	DBUser     string `env:"AUTH_DB_USER" envDefault:"app"`
	DBPassword string `env:"AUTH_DB_PASSWORD" envDefault:"app_password"`
	DBName     string `env:"AUTH_DB_NAME" envDefault:"authdb"`
	DBSSLMode  string `env:"AUTH_DB_SSLMODE" envDefault:"disable"`

	JWTSecret     string        `env:"AUTH_JWT_SECRET"`
	JWTPrivateKey string        `env:"AUTH_JWT_PRIVATE_KEY"`
	JWTPublicKey  string        `env:"AUTH_JWT_PUBLIC_KEY"`
	JWTAudience   string        `env:"AUTH_JWT_AUDIENCE" envDefault:"frontend"`
	JWTIssuer     string        `env:"AUTH_JWT_ISSUER" envDefault:"auth-service"`
	AccessTTL     time.Duration `env:"AUTH_JWT_ACCESS_TTL" envDefault:"15m"`
	RefreshTTL    time.Duration `env:"AUTH_JWT_REFRESH_TTL" envDefault:"720h"`

	NATSURL               string `env:"NATS_URL" envDefault:"nats://localhost:4222"`
	NATSVerifySubject     string `env:"NATS_SUBJECT_VERIFY_JWT" envDefault:"auth.verifyJWT"`
	NATSUserCreateSubject string `env:"NATS_SUBJECT_USER_CREATE" envDefault:"user.create-user"`
	NATSAssignRoleSubject string `env:"NATS_SUBJECT_ASSIGN_ROLE" envDefault:"rbac.assign-role"`

	TarantoolSignupURL      string `env:"TARANTOOL_SIGNUP_URL"`
	TarantoolEmailChangeURL string `env:"TARANTOOL_EMAIL_CHANGE_URL"`

	DefaultRole string `env:"AUTH_DEFAULT_ROLE" envDefault:"user"`
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
