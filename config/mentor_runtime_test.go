package config

import (
	"testing"

	"github.com/caarlos0/env/v10"
)

func TestMentorRuntimeConfigDefaultsAndExplicitOptIn(t *testing.T) {
	var cfg Config
	if env.ParseWithOptions(&cfg, env.Options{Environment: map[string]string{}}) != nil || cfg.MentorEnabled {
		t.Fatal("Mentor must be disabled by default")
	}
	values := map[string]string{"AUTH_MENTOR_ENABLED": "true", "AUTH_MENTOR_HTTPS_ADDR": "127.0.0.1:9443", "AUTH_MENTOR_NATS_URL": "tls://broker.example:4222", "AUTH_MENTOR_NATS_CREDENTIALS_FILE": "/synthetic/auth.creds"}
	if env.ParseWithOptions(&cfg, env.Options{Environment: values}) != nil || !cfg.MentorEnabled || cfg.MentorHTTPSAddress != "127.0.0.1:9443" || cfg.MentorNATSURL != "tls://broker.example:4222" || cfg.MentorNATSCredentialsFile != "/synthetic/auth.creds" {
		t.Fatal("explicit Mentor configuration did not map")
	}
}
