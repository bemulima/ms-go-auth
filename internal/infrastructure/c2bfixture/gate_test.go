package c2bfixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/example/auth-service/internal/domain"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClosedBootstrapAuthority(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Marker{Schema: "c2b-proof-ownership.v1", Project: "c2b-proof-20261016", Run: domain.C2BRun, AuthDB: "c2b_auth_20261016", RBACDB: "c2b_rbac_20261016", PublicKey: base64.StdEncoding.EncodeToString(pub), Instance: domain.C2BInstance, Submission: domain.C2BSubmission, Expires: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(m)
	file := filepath.Join(t.TempDir(), "owner.json")
	os.WriteFile(file, raw, 0600)
	t.Setenv("C2B_ENV", "c2b-proof")
	t.Setenv("C2B_FIXTURE_ENABLED", "true")
	t.Setenv("AUTH_APP_ENV", "c2b-proof")
	t.Setenv("C2B_OWNERSHIP_MARKER", file)
	dsn := "postgres://c2b_auth_fixture:private@127.0.0.1:49920/c2b_auth_20261016?sslmode=disable"
	if _, e := Gate("auth", dsn); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"postgres://c2b_auth_fixture:x@production:49920/c2b_auth_20261016", "postgres://postgres:x@127.0.0.1:49920/c2b_auth_20261016", "postgres://c2b_auth_fixture:x@127.0.0.1:49920/production"} {
		if _, e := Gate("auth", bad); e == nil {
			t.Fatal("wrong database admitted")
		}
	}
	t.Setenv("AUTH_APP_ENV", "production")
	if _, e := Gate("auth", dsn); e == nil {
		t.Fatal("production admitted")
	}
	t.Setenv("AUTH_APP_ENV", "c2b-proof")
	t.Setenv("C2B_FIXTURE_ENABLED", "false")
	if _, e := Gate("auth", dsn); e == nil {
		t.Fatal("missing enablement admitted")
	}
	t.Setenv("C2B_FIXTURE_ENABLED", "true")
	i, _ := domain.C2BActor("mentor")
	payload, _ := json.Marshal(i)
	s := domain.C2BSignedIntent{Schema: "c2b-signed-bootstrap.v1", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))}
	if got, e := Verify(m, s); e != nil || got != i {
		t.Fatal("valid fixed proof rejected")
	}
	i.Role = "admin"
	payload, _ = json.Marshal(i)
	s.Payload = base64.StdEncoding.EncodeToString(payload)
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	if _, e := Verify(m, s); e == nil {
		t.Fatal("signed admin escape admitted")
	}
	if _, e := domain.C2BActor("admin"); e == nil {
		t.Fatal("arbitrary actor accepted")
	}
	var any map[string]any
	if Strict([]byte(`{"a":1,"a":2}`), &any) == nil {
		t.Fatal("duplicate keys accepted")
	}
	if Strict([]byte(`{"a":1} {}`), &any) == nil {
		t.Fatal("trailing accepted")
	}
	os.Chmod(file, 0644)
	if _, e := Gate("auth", dsn); e == nil {
		t.Fatal("public authority file admitted")
	}
}
