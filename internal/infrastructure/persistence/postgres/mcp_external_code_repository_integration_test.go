package repo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// This is opt-in and refuses connections outside the dedicated loopback CI
// database. Each invocation creates and deletes only its own unique schema.
func TestMCPExternalCodePostgres(t *testing.T) {
	if os.Getenv("MCP_AUTH_CODE_PG_ENABLE") != "true" {
		t.Skip("requires the dedicated disposable MCP OAuth PostgreSQL fixture")
	}
	dsn := os.Getenv("MCP_AUTH_CODE_PG_DSN")
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" ||
		u.Path != "/mcp_external_codes_ci_test" || u.User == nil || u.User.Username() != "codeci" {
		t.Fatal("unsafe MCP OAuth PostgreSQL test DSN")
	}
	base, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal("cannot connect to dedicated PostgreSQL test database")
	}
	baseSQL, err := base.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = baseSQL.Close() })
	var databaseName, databaseUser string
	if err := base.Raw("SELECT current_database(), current_user").Row().Scan(&databaseName, &databaseUser); err != nil ||
		databaseName != "mcp_external_codes_ci_test" || databaseUser != "codeci" {
		t.Fatal("dedicated database identity guard failed")
	}
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	schema := "mcp_codes_" + hex.EncodeToString(entropy[:])
	if err := base.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := base.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Errorf("clean dedicated MCP schema: %v", err)
		}
	})
	q := u.Query()
	q.Set("search_path", schema+",public")
	u.RawQuery = q.Encode()
	db, err := gorm.Open(postgres.Open(u.String()), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(32)
	t.Cleanup(func() { _ = sqlDB.Close() })
	apply := func(name string) string {
		data, err := os.ReadFile(filepath.Join("../../../../migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(string(data)).Error; err != nil {
			t.Fatalf("apply isolated %s: %v", name, err)
		}
		return string(data)
	}
	apply("0001_init.up.sql")
	apply("0003_oauth_flow.up.sql")
	apply("0004_signup_completion.up.sql")
	apply("0005_email_verified.up.sql")
	apply("0006_cat49_reviewer_pending.up.sql")
	apply("0007_mcp_external_codes.up.sql")

	const studentID = "00000000-0000-4000-8000-000000000001"
	const consentID = "00000000-0000-4000-8000-000000000002"
	const clientID = "mcp-repository-ci-client"
	const redirect = "http://127.0.0.1:19191/callback"
	const resource = "https://mcp.example.test/mcp"
	if err := db.Exec("INSERT INTO auth_user(id,email,password_hash,email_verified) VALUES (?, ?, ?, true)", studentID,
		"mcp-code-fixture@example.invalid", "fixture-not-a-real-password-hash").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO auth_mcp_client(client_id,resource_uri,redirect_uris,allowed_scopes)
		VALUES (?, ?, ARRAY['http://127.0.0.1:19191/callback'], ARRAY['courses:read','tasks:read'])`, clientID, resource).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO auth_mcp_consent(id,student_id,client_id,resource_uri,granted_scopes,expires_at)
		VALUES (?, ?, ?, ?, ARRAY['courses:read','tasks:read'], ?)`, consentID, studentID, clientID,
		resource, time.Now().Add(time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	verifyMCPExternalAuthGrantPostgres(t, db, studentID, consentID, clientID, resource)

	ctx := context.Background()
	codes := NewMCPExternalCodeRepository(db)
	now := time.Now().UTC()
	makeCode := func(label string, scopes ...string) *domain.MCPExternalAuthorizationCode {
		h := sha256.Sum256([]byte("fixture:" + label))
		return &domain.MCPExternalAuthorizationCode{
			CodeHash:      hex.EncodeToString(h[:]),
			StudentID:     studentID,
			ConsentID:     consentID,
			ClientID:      clientID,
			RedirectURI:   redirect,
			ResourceURI:   resource,
			CodeChallenge: strings.Repeat("A", 43),
			Scopes:        scopes,
			ExpiresAt:     now.Add(5 * time.Minute),
		}
	}
	issue := func(label string) *domain.MCPExternalAuthorizationCode {
		code := makeCode(label, "tasks:read")
		if err := codes.CreateMCPExternalCode(ctx, code); err != nil {
			t.Fatalf("issue %s: %v", label, err)
		}
		return code
	}
	consume := func(code *domain.MCPExternalAuthorizationCode, client, uri, audience string) (*domain.MCPExternalAuthorizationCode, error) {
		return codes.ConsumeMCPExternalCode(ctx, code.CodeHash, client, uri, audience, now)
	}
	denied := func(label string, code *domain.MCPExternalAuthorizationCode) {
		t.Helper()
		if got, err := consume(code, clientID, redirect, resource); got != nil || !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s unexpectedly accepted: receipt=%v error=%v", label, got != nil, err)
		}
	}

	// The real GORM SQL adapter, not a duplicate SQL fixture, must have exactly
	// one winner under 32 concurrent PostgreSQL UPDATE ... RETURNING calls.
	first := issue("concurrent")
	results := make(chan error, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := consume(first, clientID, redirect, resource)
			if err == nil && (got == nil || got.CodeHash != first.CodeHash || len(got.Scopes) != 1 || got.Scopes[0] != "tasks:read") {
				err = errors.New("incomplete consumed code receipt")
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("unexpected consume error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent consume winners=%d, want 1", winners)
	}
	denied("replay", first)

	// An incorrect binding never consumes a valid code.
	bound := issue("binding")
	for _, tc := range []struct{ client, redirect, resource string }{
		{"other-client", redirect, resource},
		{clientID, "http://127.0.0.1:19191/other", resource},
		{clientID, redirect, "https://other.example.test/mcp"},
	} {
		got, err := consume(bound, tc.client, tc.redirect, tc.resource)
		if got != nil || !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("wrong client/redirect/resource consumed an authorization code")
		}
	}
	if got, err := consume(bound, clientID, redirect, resource); err != nil || got == nil {
		t.Fatalf("correct binding denied: %v", err)
	}

	// Persistent consent and client state are checked again at the write/read
	// boundary even when an earlier in-memory policy allowed a request.
	for _, tc := range []struct {
		label string
		alter func(*domain.MCPExternalAuthorizationCode)
	}{
		{"ungranted-scope", func(c *domain.MCPExternalAuthorizationCode) { c.Scopes = []string{"teacher:write"} }},
		{"wrong-student", func(c *domain.MCPExternalAuthorizationCode) { c.StudentID = "00000000-0000-4000-8000-000000000003" }},
		{"wrong-client", func(c *domain.MCPExternalAuthorizationCode) { c.ClientID = "unregistered-client" }},
		{"wrong-redirect", func(c *domain.MCPExternalAuthorizationCode) { c.RedirectURI = "http://127.0.0.1:19191/other" }},
		{"wrong-resource", func(c *domain.MCPExternalAuthorizationCode) { c.ResourceURI = "https://other.example.test/mcp" }},
	} {
		c := makeCode("invalid-"+tc.label, "tasks:read")
		tc.alter(c)
		if err := codes.CreateMCPExternalCode(ctx, c); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s accepted at issuance: %v", tc.label, err)
		}
	}
	expired := issue("expired")
	if err := db.Exec("UPDATE auth_mcp_authorization_code SET expires_at=clock_timestamp()-interval '1 second' WHERE code_hash=?", expired.CodeHash).Error; err != nil {
		t.Fatal(err)
	}
	denied("expired code", expired)
	revoked := issue("revoked")
	if err := db.Exec("UPDATE auth_mcp_consent SET revoked_at=clock_timestamp() WHERE id=?", consentID).Error; err != nil {
		t.Fatal(err)
	}
	denied("revoked consent", revoked)
	if err := codes.CreateMCPExternalCode(ctx, makeCode("reissue-revoked", "tasks:read")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("revoked consent issued another authorization code")
	}
	if err := db.Exec("UPDATE auth_mcp_consent SET revoked_at=NULL WHERE id=?", consentID).Error; err != nil {
		t.Fatal(err)
	}
	disabled := issue("disabled")
	if err := db.Exec("UPDATE auth_mcp_client SET disabled_at=clock_timestamp() WHERE client_id=?", clientID).Error; err != nil {
		t.Fatal(err)
	}
	denied("disabled client", disabled)
	if err := db.Exec("UPDATE auth_mcp_client SET disabled_at=NULL WHERE client_id=?", clientID).Error; err != nil {
		t.Fatal(err)
	}
	reduced := issue("scope-reduced")
	if err := db.Exec("UPDATE auth_mcp_client SET allowed_scopes=ARRAY['courses:read'] WHERE client_id=?", clientID).Error; err != nil {
		t.Fatal(err)
	}
	denied("scope reduction", reduced)
	if err := db.Exec("UPDATE auth_mcp_client SET allowed_scopes=ARRAY['courses:read','tasks:read'] WHERE client_id=?", clientID).Error; err != nil {
		t.Fatal(err)
	}
	consentScope := issue("consent-scope-reduced")
	if err := db.Exec("UPDATE auth_mcp_consent SET granted_scopes=ARRAY['courses:read'] WHERE id=?", consentID).Error; err != nil {
		t.Fatal(err)
	}
	denied("consent scope reduction", consentScope)

	// Retained evidence — even consumed/revoked — blocks DOWN and is removed
	// only by automatic destruction of this uniquely named disposable schema.
	down, err := os.ReadFile(filepath.Join("../../../../migrations", "0007_mcp_external_codes.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(string(down)).Error; err == nil {
		t.Fatal("MCP schema rollback erased retained authorization records")
	}
}

// Reuse the same fresh, owner-created PostgreSQL schema/connection as the
// single-use-code test; this adds zero shared DB or Docker lifecycle changes.
func verifyMCPExternalAuthGrantPostgres(
	t *testing.T, db *gorm.DB, studentID, consentID, clientID, resource string,
) {
	t.Helper()
	reader := NewMCPExternalAuthGrantRepository(db)
	now := time.Now().UTC()
	read := func(student, client, consent, audience string) (*domain.MCPExternalAuthGrantSnapshot, error) {
		return reader.ReadMCPExternalAuthGrant(context.Background(), student, client, consent, audience, now)
	}
	valid := func(t *testing.T) {
		t.Helper()
		got, err := read(studentID, clientID, consentID, resource)
		if err != nil || got == nil || got.StudentID != studentID ||
			got.ClientID != clientID || got.ConsentID != consentID ||
			got.ResourceURI != resource || !got.ConsentExpiresAt.After(now) ||
			!reflect.DeepEqual(got.ClientScopes, []string{"courses:read", "tasks:read"}) ||
			!reflect.DeepEqual(got.ConsentScopes, []string{"courses:read", "tasks:read"}) {
			t.Fatalf("fresh Auth grant readback malformed: %+v err=%v", got, err)
		}
	}
	denied := func(t *testing.T, label string, student, client, consent, audience string) {
		t.Helper()
		got, err := read(student, client, consent, audience)
		if got != nil || !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s: expected uniform denial, got=%+v err=%v", label, got, err)
		}
	}
	valid(t)
	denied(t, "foreign-student", "00000000-0000-4000-8000-000000000099", clientID, consentID, resource)
	denied(t, "foreign-client", studentID, "forged-client", consentID, resource)
	denied(t, "foreign-consent", studentID, clientID, "00000000-0000-4000-8000-000000000099", resource)
	denied(t, "foreign-resource", studentID, clientID, consentID, "https://other.example.test/mcp")
	denied(t, "invalid-uuid", "not-a-uuid", clientID, consentID, resource)

	apply := func(sql string, args ...any) func() error {
		return func() error { return db.Exec(sql, args...).Error }
	}
	mutations := []struct {
		name    string
		change  func() error
		restore func() error
	}{
		{"revoked-consent",
			apply("UPDATE auth_mcp_consent SET revoked_at=clock_timestamp() WHERE id=?", consentID),
			apply("UPDATE auth_mcp_consent SET revoked_at=NULL WHERE id=?", consentID)},
		{"expired-consent",
			apply("UPDATE auth_mcp_consent SET expires_at=clock_timestamp()-interval '1 second' WHERE id=?", consentID),
			apply("UPDATE auth_mcp_consent SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=?", consentID)},
		{"disabled-client",
			apply("UPDATE auth_mcp_client SET disabled_at=clock_timestamp() WHERE client_id=?", clientID),
			apply("UPDATE auth_mcp_client SET disabled_at=NULL WHERE client_id=?", clientID)},
		{"resource-drift",
			apply("UPDATE auth_mcp_client SET resource_uri=? WHERE client_id=?", "https://other.example.test/mcp", clientID),
			apply("UPDATE auth_mcp_client SET resource_uri=? WHERE client_id=?", resource, clientID)},
		{"unverified-account",
			apply("UPDATE auth_user SET email_verified=false WHERE id=?", studentID),
			apply("UPDATE auth_user SET email_verified=true WHERE id=?", studentID)},
		{"invalid-stored-scopes",
			apply("UPDATE auth_mcp_client SET allowed_scopes=ARRAY['courses:read','bad scope'] WHERE client_id=?", clientID),
			apply("UPDATE auth_mcp_client SET allowed_scopes=ARRAY['courses:read','tasks:read'] WHERE client_id=?", clientID)},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.change(); err != nil {
				t.Fatal(err)
			}
			denied(t, tc.name, studentID, clientID, consentID, resource)
			if err := tc.restore(); err != nil {
				t.Fatal(err)
			}
			valid(t)
		})
	}
	// Legitimate scope reduction must return the new exact arrays, never a
	// stale snapshot; C3B's future RBAC composite will deny removed scopes.
	if err := db.Exec("UPDATE auth_mcp_client SET allowed_scopes=ARRAY['courses:read'] WHERE client_id=?", clientID).Error; err != nil {
		t.Fatal(err)
	}
	current, err := read(studentID, clientID, consentID, resource)
	if err != nil || current == nil || !reflect.DeepEqual(current.ClientScopes, []string{"courses:read"}) {
		t.Fatalf("client scope reduction not reflected in fresh readback: %+v %v", current, err)
	}
	if err := db.Exec("UPDATE auth_mcp_client SET allowed_scopes=ARRAY['courses:read','tasks:read'] WHERE client_id=?", clientID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE auth_mcp_consent SET granted_scopes=ARRAY['courses:read'] WHERE id=?", consentID).Error; err != nil {
		t.Fatal(err)
	}
	current, err = read(studentID, clientID, consentID, resource)
	if err != nil || current == nil || !reflect.DeepEqual(current.ConsentScopes, []string{"courses:read"}) {
		t.Fatalf("consent scope reduction not reflected in fresh readback: %+v %v", current, err)
	}
	if err := db.Exec("UPDATE auth_mcp_consent SET granted_scopes=ARRAY['courses:read','tasks:read'] WHERE id=?", consentID).Error; err != nil {
		t.Fatal(err)
	}
	valid(t)
	// Even a confirmed account is not eligible during an unfinished signup
	// completion. An actual signed RBAC readback is still separately required.
	if err := db.Exec(`INSERT INTO auth_signup_completion
		(operation_id, principal_id, email, proof_fingerprint, password_hash, state,
		 principal_created, receipt_expires_at)
		VALUES ('00000000-0000-4000-8000-000000000077', ?, 'mcp-code-fixture@example.invalid', ?,
		 'synthetic', 'verified', true, clock_timestamp()+interval '1 hour')`, studentID,
		strings.Repeat("a", 64)).Error; err != nil {
		t.Fatal(err)
	}
	denied(t, "unfinished-signup", studentID, clientID, consentID, resource)
	if err := db.Exec("DELETE FROM auth_signup_completion WHERE principal_id=?", studentID).Error; err != nil {
		t.Fatal(err)
	}
	valid(t)
}
