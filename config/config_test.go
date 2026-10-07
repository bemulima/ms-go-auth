package config

import (
	"testing"
	"time"

	"github.com/caarlos0/env/v10"
)

func TestDBMigrateOnStartDefaultsToEnabled(t *testing.T) {
	t.Setenv("AUTH_DB_MIGRATE_ON_START", "")
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if !cfg.DBMigrateOnStart {
		t.Fatal("expected startup migrations to remain enabled by default")
	}
}

func TestDBMigrateOnStartCanBeDisabled(t *testing.T) {
	t.Setenv("AUTH_DB_MIGRATE_ON_START", "false")
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.DBMigrateOnStart {
		t.Fatal("expected startup migrations to be disabled")
	}
}

func TestDirectVerificationDefaultsPreserveIdentityEndpointAndTTLs(t *testing.T) {
	for _, key := range []string{"TARANTOOL_HOST", "TARANTOOL_PORT", "AUTH_VERIFICATION_SIGNUP_CODE_TTL", "AUTH_VERIFICATION_SIGNUP_HARD_TTL", "AUTH_VERIFICATION_EMAIL_CODE_TTL", "AUTH_VERIFICATION_EMAIL_HARD_TTL"} {
		t.Setenv(key, "")
	}
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		t.Fatal("parse direct verification config")
	}
	if cfg.TarantoolHost != "localhost" || cfg.TarantoolPort != "3301" || cfg.VerificationSignupCodeTTL != 5*time.Minute || cfg.VerificationSignupHardTTL != 24*time.Hour || cfg.VerificationEmailCodeTTL != 5*time.Minute || cfg.VerificationEmailHardTTL != 24*time.Hour {
		t.Fatal("direct verification default contract changed")
	}
}
