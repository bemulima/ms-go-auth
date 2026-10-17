package config

import (
	"errors"
	"net"
	"net/url"
)

func (c *Config) ValidateC2BProof() error {
	if !c.C2BProofEnabled {
		return nil
	}
	if c.AppEnv != "c2b-proof" || c.HTTPHost != "127.0.0.1" || c.DBHost != "127.0.0.1" || c.DBName != "c2b_auth_20261016" || c.DBUser != "c2b_auth_runtime" || c.DBMigrateOnStart {
		return errors.New("C2-B runtime requires isolated owner-migrated loopback database")
	}
	return nil
}
func (c *Config) C2BDatabaseURL() string {
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort(c.DBHost, c.DBPort), User: url.UserPassword(c.DBUser, c.DBPassword), Path: "/" + c.DBName, RawQuery: "sslmode=" + c.DBSSLMode}
	return u.String()
}
