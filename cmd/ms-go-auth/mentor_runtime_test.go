package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/auth-service/config"
	internalhttp "github.com/example/auth-service/internal/transport/http/private"
	"github.com/nats-io/nkeys"
)

func mentorRuntimeFixture(t *testing.T) (*config.Config, mentorRuntimeLoaders, MentorCompositionDependencies, *compositionSQL, *compositionRequester, string) {
	t.Helper()
	composition, deps, sql, owners, token := compositionFixture(t)
	_, access := compositionKey(t, 0)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("ephemeral TLS key unavailable")
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "auth.example"}, DNSNames: []string{"auth.example"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("ephemeral TLS certificate unavailable")
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cfg := &config.Config{MentorEnabled: true, HTTPHost: "127.0.0.1", HTTPPort: "8081", MentorHTTPSAddress: "127.0.0.1:9443", MentorTLSCertFile: "/synthetic/auth.crt", MentorTLSKeyFile: "/synthetic/auth.key", MentorNATSURL: "tls://broker.example:4222", MentorNATSCredentialsFile: "/synthetic/auth.creds", JWTPrivateKey: access.PrivatePEM, JWTPublicKey: access.PublicPEM, JWTIssuer: "composition-source", JWTAudience: "composition-client", MentorRolePrivateKey: composition.RoleDecision.PrivatePEM, MentorRolePublicKey: composition.RoleDecision.PublicPEM, MentorLookupPrivateKey: composition.OwnerLookup.PrivatePEM, MentorLookupPublicKey: composition.OwnerLookup.PublicPEM, MentorRBACReplyPublicKey: composition.RBACReplyPublicPEM, MentorIntentReplyPublicKey: composition.MentorReplyPublicPEM}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("ephemeral user NKey unavailable")
	}
	t.Cleanup(user.Wipe)
	public, _ := user.PublicKey()
	seed, _ := user.Seed()
	// Only local subject/seed consistency is exercised here. A real broker must
	// separately validate credential issuer, expiry and ACLs; no broker is run.
	credentialJWT := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ed25519-nkey","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":%q}`, public))) + ".c3ludGhldGlj"
	credential := []byte("-----BEGIN NATS USER JWT-----\n" + credentialJWT + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
	loaders := mentorRuntimeLoaders{tlsPair: func(string, string) (tls.Certificate, error) { return certificate, nil }, readFile: func(string, bool) ([]byte, error) { return credential, nil }, now: func() time.Time { return now }}
	return cfg, loaders, deps, sql, owners, token
}

func TestMentorRuntimeDisabledSkipsFilesKeysAndDependencies(t *testing.T) {
	cfg := &config.Config{MentorEnabled: false, DBMigrateOnStart: true, MentorNATSURL: "invalid", MentorTLSCertFile: "invalid"}
	loaders := mentorRuntimeLoaders{tlsPair: func(string, string) (tls.Certificate, error) { panic("disabled TLS read") }, readFile: func(string, bool) ([]byte, error) { panic("disabled file read") }}
	if got, err := prepareMentorRuntime(cfg, loaders); got != nil || err != nil {
		t.Fatal("disabled runtime not inert")
	}
}

func TestMentorRuntimePreflightAndDedicatedHTTPS(t *testing.T) {
	cfg, loaders, deps, sql, owners, token := mentorRuntimeFixture(t)
	prepared, err := prepareMentorRuntime(cfg, loaders)
	if err != nil || prepared == nil {
		t.Fatal("valid enabled preflight unavailable")
	}
	if sql.connects != 0 || owners.adminCalls != 0 {
		t.Fatal("preflight contacted dependency")
	}
	if prepared.natsOptions.Url != cfg.MentorNATSURL || prepared.natsOptions.AllowReconnect || prepared.natsOptions.RetryOnFailedConnect || prepared.natsOptions.UserJWT == nil || prepared.natsOptions.SignatureCB == nil || prepared.natsOptions.TLSConfig == nil || prepared.natsOptions.TLSConfig.InsecureSkipVerify || prepared.natsOptions.TLSConfig.ServerName != "broker.example" || prepared.natsOptions.TLSConfig.MinVersion < tls.VersionTLS12 || prepared.natsOptions.Timeout <= 0 || prepared.natsOptions.Timeout > 5*time.Second {
		t.Fatal("broker options are not authenticated bounded TLS")
	}
	server, err := newMentorHTTPSServer(prepared, deps)
	if err != nil || server == nil || server.Handler == nil || server.Addr != cfg.MentorHTTPSAddress || server.TLSConfig == nil || server.TLSConfig.MinVersion < tls.VersionTLS12 || len(server.TLSConfig.Certificates) != 1 {
		t.Fatal("dedicated HTTPS composition missing")
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadHeaderTimeout > 3*time.Second || server.ReadTimeout <= 0 || server.ReadTimeout > 5*time.Second || server.WriteTimeout <= 0 || server.WriteTimeout > 10*time.Second || server.IdleTimeout <= 0 || server.MaxHeaderBytes > 16384 || server.ErrorLog == nil {
		t.Fatal("HTTPS deadlines/log boundary missing")
	}
	response := compositionHTTP(server.Handler, internalhttp.MentorSessionVerifyPath, "{}", token)
	if response.Code != http.StatusOK || sql.queries != 1 || owners.adminCalls != 0 {
		t.Fatal("actual composed handler not reached through server")
	}
}

func TestMentorRuntimePreflightRejectsUnsafeConfiguration(t *testing.T) {
	cfg, loaders, _, _, _, _ := mentorRuntimeFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"migrations", func(c *config.Config) { c.DBMigrateOnStart = true }},
		{"missing address", func(c *config.Config) { c.MentorHTTPSAddress = "" }},
		{"same HTTP port", func(c *config.Config) { c.MentorHTTPSAddress = "127.0.0.1:8081" }},
		{"ephemeral port", func(c *config.Config) { c.MentorHTTPSAddress = "127.0.0.1:0" }},
		{"plain broker", func(c *config.Config) { c.MentorNATSURL = "nats://broker.example:4222" }},
		{"embedded broker credentials", func(c *config.Config) { c.MentorNATSURL = "tls://user:secret@broker.example:4222" }},
		{"broker fallback", func(c *config.Config) { c.MentorNATSURL += ",tls://other.example:4222" }},
		{"broker query", func(c *config.Config) { c.MentorNATSURL += "?x=1" }},
		{"broker fragment", func(c *config.Config) { c.MentorNATSURL += "#x" }},
		{"no broker port", func(c *config.Config) { c.MentorNATSURL = "tls://broker.example" }},
		{"missing credentials", func(c *config.Config) { c.MentorNATSCredentialsFile = "" }},
		{"relative TLS path", func(c *config.Config) { c.MentorTLSKeyFile = "key.pem" }},
		{"lookup reused as role", func(c *config.Config) {
			c.MentorRolePrivateKey = c.MentorLookupPrivateKey
			c.MentorRolePublicKey = c.MentorLookupPublicKey
		}},
		{"access key reused as role", func(c *config.Config) {
			c.MentorRolePrivateKey = c.JWTPrivateKey
			c.MentorRolePublicKey = c.JWTPublicKey
		}},
		{"reviewer reply reused", func(c *config.Config) { c.RBACPermissionDecisionPublicKey = c.MentorRBACReplyPublicKey }},
		{"mismatched role", func(c *config.Config) { c.MentorRolePrivateKey = c.MentorLookupPrivateKey }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := *cfg
			tc.mutate(&changed)
			if got, err := prepareMentorRuntime(&changed, loaders); got != nil || err != ErrMentorRuntimeUnavailable {
				t.Fatal("unsafe enabled configuration accepted or diagnostics leaked")
			}
		})
	}
	for _, which := range []string{"TLS", "credential", "clock", "expired TLS", "TLS key reuse"} {
		t.Run(which, func(t *testing.T) {
			changed := loaders
			switch which {
			case "TLS":
				changed.tlsPair = func(string, string) (tls.Certificate, error) {
					return tls.Certificate{}, errors.New("sensitive file error")
				}
			case "credential":
				changed.readFile = func(string, bool) ([]byte, error) { return nil, errors.New("sensitive credential detail") }
			case "clock":
				changed.now = func() time.Time { return time.Time{} }
			case "expired TLS":
				changed.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
			case "TLS key reuse":
				changed.tlsPair = func(a, b string) (tls.Certificate, error) {
					cert, err := loaders.tlsPair(a, b)
					key, _ := compositionKey(t, 1)
					cert.PrivateKey = key
					return cert, err
				}
			}
			if got, err := prepareMentorRuntime(cfg, changed); got != nil || err != ErrMentorRuntimeUnavailable {
				t.Fatal("unsafe key/TLS preflight accepted")
			}
		})
	}
}

func TestMentorRuntimeLifecycleClosesBothServers(t *testing.T) {
	for _, cause := range []string{"cancel", "legacy failure", "HTTPS failure", "broker failure"} {
		t.Run(cause, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			brokerDone := make(chan struct{})
			started := make(chan int, 2)
			release := make([]chan struct{}, 2)
			fail := make([]chan struct{}, 2)
			var once [2]sync.Once
			var stops atomic.Int32
			servers := make([]mentorServerLifecycle, 2)
			for i := range servers {
				i := i
				release[i] = make(chan struct{})
				fail[i] = make(chan struct{})
				servers[i] = mentorServerLifecycle{start: func() error {
					started <- i
					select {
					case <-release[i]:
						return http.ErrServerClosed
					case <-fail[i]:
						return errors.New("sensitive listener error")
					}
				}, shutdown: func(ctx context.Context) error {
					if d, ok := ctx.Deadline(); !ok || time.Until(d) > 5*time.Second {
						t.Error("shutdown not bounded")
					}
					stops.Add(1)
					once[i].Do(func() { close(release[i]) })
					return nil
				}, close: func() error { once[i].Do(func() { close(release[i]) }); return nil }}
			}
			done := make(chan error, 1)
			go func() { done <- runMentorServers(ctx, servers, brokerDone) }()
			for range servers {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("server lifecycle did not start")
				}
			}
			switch cause {
			case "cancel":
				cancel()
			case "legacy failure":
				close(fail[0])
			case "HTTPS failure":
				close(fail[1])
			case "broker failure":
				close(brokerDone)
			}
			select {
			case err := <-done:
				if (cause == "cancel" && err != nil) || (cause != "cancel" && err != ErrMentorRuntimeUnavailable) || stops.Load() != 2 {
					t.Fatal("lifecycle did not stop both servers with sanitized outcome")
				}
			case <-time.After(time.Second):
				t.Fatal("lifecycle failed to stop")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls int
	if err := runMentorServers(ctx, []mentorServerLifecycle{{start: func() error { calls++; return nil }}}, nil); err != nil || calls != 0 {
		t.Fatal("cancelled lifecycle started listener")
	}
	closed := make(chan struct{})
	close(closed)
	servers := []mentorServerLifecycle{{start: func() error { calls++; return nil }, shutdown: func(context.Context) error { return nil }, close: func() error { return nil }}, {start: func() error { calls++; return nil }, shutdown: func(context.Context) error { return nil }, close: func() error { return nil }}}
	if err := runMentorServers(context.Background(), servers, closed); err != ErrMentorRuntimeUnavailable || calls != 0 {
		t.Fatal("known closed broker started listeners")
	}
}

func TestMentorRuntimeBoundedPrivateFileSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-input")
	if os.WriteFile(path, []byte("first synthetic snapshot"), 0600) != nil {
		t.Fatal("synthetic file unavailable")
	}
	raw, err := readMentorRuntimeFile(path, true)
	if err != nil || string(raw) != "first synthetic snapshot" {
		t.Fatal("bounded owner-only snapshot unavailable")
	}
	if os.WriteFile(path, []byte("replacement"), 0600) != nil || string(raw) != "first synthetic snapshot" {
		t.Fatal("read snapshot changed after file replacement")
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("synthetic mode unavailable")
	}
	if raw, err := readMentorRuntimeFile(path, true); raw != nil || err != ErrMentorRuntimeUnavailable {
		t.Fatal("non-owner-only private file accepted")
	}
	if _, err := readMentorRuntimeFile(path, false); err != nil {
		t.Fatal("public certificate permissions rejected")
	}
	if os.WriteFile(path, []byte(strings.Repeat("x", mentorRuntimeFileLimit+1)), 0600) != nil {
		t.Fatal("synthetic oversize unavailable")
	}
	if raw, err := readMentorRuntimeFile(path, false); raw != nil || err != ErrMentorRuntimeUnavailable {
		t.Fatal("oversized file accepted")
	}
	for _, path := range []string{"relative-input", filepath.Dir(path), filepath.Join(filepath.Dir(path), "missing")} {
		if raw, err := readMentorRuntimeFile(path, true); raw != nil || err != ErrMentorRuntimeUnavailable {
			t.Fatal("invalid file admitted or diagnostics leaked")
		}
	}
}

func TestMentorRuntimeCredentialSnapshotUsesNativePairCheck(t *testing.T) {
	cfg, loaders, _, _, _, _ := mentorRuntimeFixture(t)
	reads := 0
	original := loaders.readFile
	loaders.readFile = func(p string, private bool) ([]byte, error) { reads++; return original(p, private) }
	prepared, err := prepareMentorRuntime(cfg, loaders)
	if err != nil || reads != 1 {
		t.Fatal("credential snapshot preflight unavailable")
	}
	if !mentorRuntimeCredentialPair(prepared.natsOptions) || reads != 1 {
		t.Fatal("native credentials reread file or failed pair consistency")
	}
	foreign, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("ephemeral foreign key unavailable")
	}
	defer foreign.Wipe()
	options := prepared.natsOptions
	options.SignatureCB = foreign.Sign
	if mentorRuntimeCredentialPair(options) {
		t.Fatal("JWT subject accepted a foreign seed")
	}
}

func TestMentorRuntimePrivateFileRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-private")
	if os.WriteFile(path, []byte("synthetic content"), 0600) != nil || os.Symlink(path, path+"-link") != nil {
		t.Fatal("synthetic symlink fixture unavailable")
	}
	if raw, err := readMentorRuntimeFile(path+"-link", true); raw != nil || err != ErrMentorRuntimeUnavailable {
		t.Fatal("private configuration followed a symlink")
	}
}
