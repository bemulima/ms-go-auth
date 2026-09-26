package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPasswordUsesBoundedStdinAndDoesNotEcho(t *testing.T) {
	const password = "verification-private-password"
	got, err := readPassword(strings.NewReader(password))
	if err != nil || got != password {
		t.Fatalf("readPassword() = %q, %v", got, err)
	}
	if _, err := readPassword(strings.NewReader(password + "\nsecond-line")); err == nil {
		t.Fatal("expected multiline password input rejection")
	}
	if _, err := readPassword(strings.NewReader(strings.Repeat("x", 513))); err == nil {
		t.Fatal("expected oversized input rejection")
	}
	var stdout, stderr bytes.Buffer
	_ = json.NewEncoder(&stdout).Encode(safeOutput{Status: "created", RunID: "abc12345", IdentityID: "53b0d885-86e5-5c9c-a123-693f9d1ac301", Role: "student"})
	if strings.Contains(stdout.String()+stderr.String(), password) {
		t.Fatal("fixture output contains password")
	}
}

func TestFixtureSafetyGateRequiresDisposableMarkerAndNoJWTSignerSecret(t *testing.T) {
	t.Setenv("AUTH_VERIFICATION_FIXTURE_ENABLED", "true")
	t.Setenv("AUTH_APP_ENV", "v1-r0")
	t.Setenv("AUTH_DB_HOST", "auth-db")
	t.Setenv("AUTH_DB_PORT", "5432")
	t.Setenv("AUTH_DB_USER", "v1_auth")
	t.Setenv("AUTH_DB_PASSWORD", "private-runtime-db-secret")
	t.Setenv("AUTH_DB_NAME", "v1_auth")
	t.Setenv("AUTH_DB_MIGRATE_ON_START", "false")
	t.Setenv("NATS_URL", "nats://nats:4222")
	t.Setenv("NATS_SUBJECT_ASSIGN_ROLE", "rbac.assign-role")
	t.Setenv("NATS_SUBJECT_CHECK_ROLE", "rbac.checkRole")
	t.Setenv("AUTH_JWT_SECRET", "")
	t.Setenv("AUTH_JWT_PRIVATE_KEY", "")
	t.Setenv("AUTH_JWT_PUBLIC_KEY", "")
	marker := ownershipMarker{SchemaVersion: 1, Purpose: "v1-a-auth-fixture", RunID: "abc12345", Project: "lp-v1-abc12345", Network: "lp-v1-abc12345-net"}
	data, _ := json.Marshal(marker)
	path := filepath.Join(t.TempDir(), "ownership.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSafetyAt("abc12345", path); err != nil {
		t.Fatalf("expected valid disposable marker: %v", err)
	}
	t.Setenv("AUTH_VERIFICATION_FIXTURE_ENABLED", "false")
	if err := validateSafetyAt("abc12345", path); err == nil {
		t.Fatal("expected explicit fixture gate")
	}
	t.Setenv("AUTH_VERIFICATION_FIXTURE_ENABLED", "true")
	t.Setenv("AUTH_JWT_SECRET", "unexpected-signing-secret")
	if err := validateSafetyAt("abc12345", path); err == nil {
		t.Fatal("fixture runner must reject an available JWT signing secret")
	}
	t.Setenv("AUTH_JWT_SECRET", "")
	t.Setenv("NATS_SUBJECT_ASSIGN_ROLE", "unexpected.subject")
	if err := validateSafetyAt("abc12345", path); err == nil {
		t.Fatal("fixture runner must reject a non-owner role assignment subject")
	}
}
