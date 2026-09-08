package config

import (
	"testing"

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
