package config

import "testing"

func TestC2BProofRuntimeFailClosed(t *testing.T) {
	c := Config{C2BProofEnabled: true, AppEnv: "c2b-proof", HTTPHost: "127.0.0.1", DBHost: "127.0.0.1", DBUser: "c2b_auth_runtime", DBName: "c2b_auth_20261016", DBMigrateOnStart: false}
	if c.ValidateC2BProof() != nil {
		t.Fatal("valid loopback proof denied")
	}
	for _, mutate := range []func(*Config){func(x *Config) { x.AppEnv = "production" }, func(x *Config) { x.DBUser = "postgres" }, func(x *Config) { x.DBName = "production" }, func(x *Config) { x.DBHost = "database" }, func(x *Config) { x.HTTPHost = "0.0.0.0" }, func(x *Config) { x.DBMigrateOnStart = true }} {
		x := c
		mutate(&x)
		if x.ValidateC2BProof() == nil {
			t.Fatal("production-capable runtime accepted")
		}
	}
}
