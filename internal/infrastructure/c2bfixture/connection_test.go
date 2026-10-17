package c2bfixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/example/auth-service/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureEnvironment(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PG") {
			t.Setenv(key, "")
			os.Unsetenv(key)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("test key generation failed")
	}
	m := Marker{Schema: "c2b-proof-ownership.v1", Project: "c2b-proof-20261016", Run: domain.C2BRun, AuthDB: "c2b_auth_20261016", RBACDB: "c2b_rbac_20261016", PublicKey: base64.StdEncoding.EncodeToString(pub), Instance: domain.C2BInstance, Submission: domain.C2BSubmission, Expires: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "owner.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("test marker write failed")
	}
	t.Setenv("C2B_OWNERSHIP_MARKER", path)
	t.Setenv("C2B_ENV", "c2b-proof")
	t.Setenv("C2B_FIXTURE_ENABLED", "true")
	t.Setenv("AUTH_APP_ENV", "c2b-proof")
	return priv
}
func fixtureDSN() string {
	return "postgres://c2b_auth_fixture:test-only-password@127.0.0.1:49920/c2b_auth_20261016?sslmode=disable"
}
func deniedDSNs() map[string]string {
	base := fixtureDSN()
	return map[string]string{
		"host":             base + "&host=203.0.113.1",
		"port":             base + "&port=5432",
		"user":             base + "&user=postgres",
		"dbname":           base + "&dbname=other",
		"database":         base + "&database=other",
		"hostaddr":         base + "&hostaddr=203.0.113.1",
		"service":          base + "&service=other",
		"servicefile":      base + "&servicefile=/tmp/unowned",
		"duplicate":        base + "&sslmode=disable",
		"encoded_key":      base + "&%68ost=203.0.113.1",
		"encoded_option":   strings.Replace(base, "sslmode=disable", "sslmode=%64isable", 1),
		"encoded_path":     strings.Replace(base, "/c2b_", "/%632b_", 1),
		"encoded_user":     strings.Replace(base, "postgres://c2b_", "postgres://%632b_", 1),
		"remote_fallback":  strings.Replace(base, "127.0.0.1:49920", "127.0.0.1:49920,203.0.113.1:49920", 1),
		"wrong_port":       strings.Replace(base, ":49920", ":5432", 1),
		"remote":           strings.Replace(base, "127.0.0.1", "203.0.113.1", 1),
		"localhost_alias":  strings.Replace(base, "127.0.0.1", "localhost", 1),
		"database_path":    strings.Replace(base, "/c2b_auth_20261016", "/other", 1),
		"user_authority":   strings.Replace(base, "c2b_auth_fixture:", "postgres:", 1),
		"options":          base + "&options=-csearch_path%3Dpublic",
		"unexpected":       base + "&application_name=other",
		"empty_query_pair": base + "&",
		"fragment":         base + "#other",
		"missing_password": strings.Replace(base, ":test-only-password@", "@", 1),
		"empty_password":   strings.Replace(base, "test-only-password", "", 1),
		"prefer_tls":       strings.Replace(base, "sslmode=disable", "sslmode=prefer", 1),
	}
}

func TestEffectiveConnectionRejectsOverrides(t *testing.T) {
	fixtureEnvironment(t)
	for name, dsn := range deniedDSNs() {
		t.Run(name, func(t *testing.T) {
			_, config, err := PrepareConnection("auth", dsn)
			if err == nil || config != nil {
				t.Fatal("unsafe configuration admitted")
			}
			if strings.Contains(err.Error(), "test-only-password") {
				t.Fatal("credential-bearing error")
			}
		})
	}
	for _, key := range []string{"PGHOST", "PGHOSTADDR", "PGPORT", "PGUSER", "PGDATABASE", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGOPTIONS", "PGSSLMODE", "PGUNKNOWN"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "unowned")
			_, config, err := PrepareConnection("auth", fixtureDSN())
			if err == nil || config != nil {
				t.Fatal("environment authority admitted")
			}
		})
	}
	t.Run("empty_PGHOST", func(t *testing.T) {
		t.Setenv("PGHOST", "")
		_, c, e := PrepareConnection("auth", fixtureDSN())
		if e == nil || c != nil {
			t.Fatal("empty environment default admitted")
		}
	})
	t.Run("production", func(t *testing.T) {
		t.Setenv("AUTH_APP_ENV", "production")
		_, c, e := PrepareConnection("auth", fixtureDSN())
		if e == nil || c != nil {
			t.Fatal("production admitted")
		}
	})
}
func TestEffectiveConnectionPreservesFixedIdentity(t *testing.T) {
	fixtureEnvironment(t)
	_, config, err := PrepareConnection("auth", fixtureDSN())
	if err != nil {
		t.Fatal("legitimate fixture denied")
	}
	c := config
	if c.Host != "127.0.0.1" || c.Port != 49920 || c.User != "c2b_auth_fixture" || c.Database != "c2b_auth_20261016" || c.Password != "test-only-password" || c.TLSConfig != nil || len(c.Fallbacks) != 0 || len(c.RuntimeParams) != 0 {
		t.Fatal("effective identity changed")
	}
	// Password escaping must not be confused with encoded connection parameters.
	_, _, err = PrepareConnection("auth", strings.Replace(fixtureDSN(), "test-only-password", "test%40only%3Apassword", 1))
	if err != nil {
		t.Fatal("escaped password rejected")
	}
}

func TestEffectiveRuntimeConnectionUsesFixedPrincipal(t *testing.T) {
	fixtureEnvironment(t)
	t.Setenv("AUTH_C2B_PROOF_ENABLED", "true")
	dsn := strings.Replace(fixtureDSN(), "c2b_auth_fixture:", "c2b_auth_runtime:", 1)
	_, c, e := PrepareConnection("auth-runtime", dsn)
	if e != nil || c == nil || c.User != "c2b_auth_runtime" || c.Port != 49920 {
		t.Fatal("legitimate runtime configuration rejected")
	}
	_, c, e = PrepareConnection("auth-runtime", dsn+"&host=203.0.113.1")
	if e == nil || c != nil {
		t.Fatal("runtime endpoint override accepted")
	}
}
