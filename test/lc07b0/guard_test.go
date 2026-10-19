// Package lc07b0_test contains an opt-in, disposable owner fixture, never a server capability.
package lc07b0_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const owner = "auth"
const targetInstance = "87d2e602-782b-42bf-a1c8-93d69a9c131e"
const targetSubmission = "c2e39f7c-f9a3-4c9b-b6a3-aab527bec86c"

type marker struct {
	Schema     string    `json:"schema"`
	Run        string    `json:"run"`
	Project    string    `json:"project"`
	Network    string    `json:"network"`
	Nonce      string    `json:"nonce"`
	Instance   string    `json:"instance"`
	Submission string    `json:"submission"`
	Expires    time.Time `json:"expires"`
	PGPort     int       `json:"pg_port"`
	NATSPort   int       `json:"nats_port"`
}
type privateConfig struct {
	DSN     string `json:"dsn"`
	NATSURL string `json:"nats_url"`
}

func privateRead(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("private file required")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !ownedByCurrentUser(stat.Uid) {
		return nil, errors.New("private owner required")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("private file unavailable")
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return nil, errors.New("private file changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 {
		return nil, errors.New("private file bounds")
	}
	return b, nil
}
func strict(b []byte, v any) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid fixture input")
	}
	return nil
}
func validate(m marker) error {
	now := time.Now().UTC()
	if m.Schema != "lc07-b0-owner-fixture.v1" || !regexp.MustCompile(`^[a-f0-9]{12}$`).MatchString(m.Run) || m.Project != "lc07-b0-"+m.Run || m.Network != m.Project+"-net" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(m.Nonce) || m.Instance != targetInstance || m.Submission != targetSubmission || !m.Expires.After(now) || m.Expires.After(now.Add(2*time.Hour)) || m.PGPort < 1024 || m.PGPort > 65535 || m.NATSPort < 1024 || m.NATSPort > 65535 {
		return errors.New("fixture ownership denied")
	}
	return nil
}
func identity(run, actor string) (string, string) {
	sum := sha256.Sum256([]byte("lc07-b0:" + run + ":" + actor))
	sum[6] = (sum[6] & 15) | 80
	sum[8] = (sum[8] & 63) | 128
	h := hex.EncodeToString(sum[:16])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], actor + "+lc07b0" + run + "@verification.invalid"
}
func parseDSN(m marker, raw string) (*pgx.ConnConfig, error) {
	for _, v := range os.Environ() {
		if strings.HasPrefix(strings.SplitN(v, "=", 2)[0], "PG") {
			return nil, errors.New("PG environment denied")
		}
	}
	u, e := url.Parse(raw)
	database := "lc07_b0_" + m.Run + "_" + owner
	if e != nil || u.Scheme != "postgres" || u.Host != "127.0.0.1:"+strconv.Itoa(m.PGPort) || u.Path != "/"+database || u.RawPath != "" || u.Fragment != "" || u.RawQuery != "sslmode=disable" || u.User == nil || u.User.Username() != database+"_bootstrap" {
		return nil, errors.New("fixture destination denied")
	}
	pw, ok := u.User.Password()
	if !ok || len(pw) < 16 {
		return nil, errors.New("private credential required")
	}
	cfg, e := pgx.ParseConfig(raw)
	if e != nil || cfg.Host != "127.0.0.1" || int(cfg.Port) != m.PGPort || cfg.Database != database || cfg.User != database+"_bootstrap" || cfg.TLSConfig != nil || len(cfg.Fallbacks) != 0 || len(cfg.RuntimeParams) != 0 {
		return nil, errors.New("effective destination denied")
	}
	return cfg, nil
}
func load(t *testing.T) (string, marker, privateConfig, string) {
	t.Helper()
	if os.Getenv("LC07_B0_ENABLED") != "true" {
		t.Skip("explicit disposable LC07-B0 fixture only")
	}
	if os.Getenv("AUTH_JWT_SECRET") != "" || os.Getenv("AUTH_JWT_PRIVATE_KEY") != "" {
		t.Fatal("bootstrap must not possess token signing authority")
	}
	dir := os.Getenv("LC07_B0_DIR")
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private fixture directory required")
	}
	raw, e := privateRead(filepath.Join(dir, "ownership.json"))
	if e != nil {
		t.Fatal("private marker unavailable")
	}
	var m marker
	if strict(raw, &m) != nil || validate(m) != nil {
		t.Fatal("fixture ownership denied")
	}
	raw, e = privateRead(filepath.Join(dir, owner+"-bootstrap.json"))
	if e != nil {
		t.Fatal("private configuration unavailable")
	}
	var c privateConfig
	if strict(raw, &c) != nil {
		t.Fatal("invalid fixture configuration")
	}
	cfg, e := parseDSN(m, c.DSN)
	if e != nil {
		t.Fatal("fixture destination denied")
	}
	_ = cfg
	digest := ownershipDigest(m)
	checkReceipt(t, dir, owner, digest, m)
	return dir, m, c, digest
}
func openOwned(t *testing.T, m marker, c privateConfig, digest string) *pgx.Conn {
	t.Helper()
	cfg, e := parseDSN(m, c.DSN)
	if e != nil {
		t.Fatal("fixture destination denied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal("fixture connection failed")
	}
	var database, user, comment string
	e = conn.QueryRow(ctx, `SELECT current_database(),current_user,coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=current_database()`).Scan(&database, &user, &comment)
	if e != nil || database != cfg.Database || user != cfg.User || comment != "lc07-b0:"+digest {
		_ = conn.Close(ctx)
		t.Fatal("actual database ownership mismatch")
	}
	return conn
}
func validReceipt(raw []byte, owner, digest string, m marker) bool {
	var got struct {
		Schema     string            `json:"schema"`
		Owner      string            `json:"owner"`
		Digest     string            `json:"ownership_digest"`
		Run        string            `json:"run"`
		Identities map[string]string `json:"identities"`
		Instance   string            `json:"instance"`
		Submission string            `json:"submission"`
	}
	if strict(raw, &got) != nil || got.Schema != "lc07-b0-bootstrap-receipt.v1" || got.Owner != owner || got.Digest != digest || got.Run != m.Run || got.Instance != m.Instance || got.Submission != m.Submission || len(got.Identities) != 3 {
		return false
	}
	for _, actor := range []string{"admin", "student", "teacher"} {
		id, _ := identity(m.Run, actor)
		if got.Identities[actor] != id {
			return false
		}
	}
	return true
}
func checkReceipt(t *testing.T, dir, owner, digest string, m marker) {
	t.Helper()
	p := filepath.Join(dir, owner+"-receipt.json")
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		return
	}
	old, e := privateRead(p)
	if e != nil || !validReceipt(old, owner, digest, m) {
		t.Fatal("receipt replay conflict")
	}
}

func receipt(t *testing.T, dir, owner, digest string, m marker) {
	t.Helper()
	rows := map[string]string{}
	for _, actor := range []string{"admin", "student", "teacher"} {
		id, _ := identity(m.Run, actor)
		rows[actor] = id
	}
	raw, _ := json.Marshal(map[string]any{"schema": "lc07-b0-bootstrap-receipt.v1", "owner": owner, "ownership_digest": digest, "run": m.Run, "identities": rows, "instance": m.Instance, "submission": m.Submission})
	p := filepath.Join(dir, owner+"-receipt.json")
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(e) {
		old, e := privateRead(p)
		if e != nil || string(old) != string(raw) {
			t.Fatal("receipt replay conflict")
		}
		return
	}
	if e != nil {
		t.Fatal("receipt unavailable")
	}
	defer f.Close()
	if _, e = f.Write(raw); e != nil {
		t.Fatal("receipt unavailable")
	}
}
func TestOwnershipGuards(t *testing.T) {
	good := marker{Schema: "lc07-b0-owner-fixture.v1", Run: "0123456789ab", Project: "lc07-b0-0123456789ab", Network: "lc07-b0-0123456789ab-net", Nonce: strings.Repeat("a", 64), Instance: targetInstance, Submission: targetSubmission, Expires: time.Now().Add(time.Hour), PGPort: 55432, NATSPort: 54222}
	if validate(good) != nil {
		t.Fatal("valid isolated marker rejected")
	}
	for _, change := range []func(*marker){func(m *marker) { m.Project = "production" }, func(m *marker) { m.Network = "ms-net" }, func(m *marker) { m.Instance = "other" }, func(m *marker) { m.Submission = "other" }, func(m *marker) { m.Expires = time.Now().Add(-time.Second) }, func(m *marker) { m.Expires = time.Now().Add(24 * time.Hour) }, func(m *marker) { m.Nonce = "" }} {
		m := good
		change(&m)
		if validate(m) == nil {
			t.Fatal("invalid ownership accepted")
		}
	}
	base := "postgres://lc07_b0_0123456789ab_" + owner + "_bootstrap:private-placeholder@127.0.0.1:55432/lc07_b0_0123456789ab_" + owner + "?sslmode=disable"
	if _, e := parseDSN(good, base); e != nil {
		t.Fatal("valid destination rejected")
	}
	for _, raw := range []string{strings.Replace(base, "127.0.0.1", "localhost", 1), base + "&host=production", base + "&sslmode=disable", strings.Replace(base, "_bootstrap:", "_runtime:", 1), strings.Replace(base, "sslmode=disable", "sslmode=require", 1), base + "#fragment"} {
		if _, e := parseDSN(good, raw); e == nil {
			t.Fatal("destination override admitted")
		}
	}
	t.Setenv("PGSERVICE", "foreign")
	if _, e := parseDSN(good, base); e == nil {
		t.Fatal("PG override admitted")
	}
	a, _ := identity(good.Run, "admin")
	b, _ := identity(good.Run, "student")
	if a == b || !strings.Contains(fmt.Sprint(a), "-") {
		t.Fatal("run identities not distinct")
	}
}

func ownedByCurrentUser(uid uint32) bool { return uid == uint32(os.Getuid()) }
func ownershipDigest(m marker) string {
	raw, _ := json.Marshal(m)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func TestPrivateAndReplayGuards(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "private.json")
	if os.WriteFile(p, []byte(`{"schema":"valid"}`), 0600) != nil {
		t.Fatal("test setup")
	}
	if _, e := privateRead(p); e != nil {
		t.Fatal("private file rejected")
	}
	if !ownedByCurrentUser(uint32(os.Getuid())) || ownedByCurrentUser(uint32(os.Getuid())+1) {
		t.Fatal("file ownership gate")
	}
	if os.Chmod(p, 0644) != nil {
		t.Fatal("test setup")
	}
	if _, e := privateRead(p); e == nil {
		t.Fatal("public credential admitted")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(p, link) != nil {
		t.Fatal("test setup")
	}
	if _, e := privateRead(link); e == nil {
		t.Fatal("symlink admitted")
	}
	for _, raw := range []string{`{"schema":"x","unknown":true}`, `{"schema":"x"}{}`} {
		var v struct {
			Schema string `json:"schema"`
		}
		if strict([]byte(raw), &v) == nil {
			t.Fatal("non-strict input admitted")
		}
	}
	m := marker{Schema: "lc07-b0-owner-fixture.v1", Run: "0123456789ab", Project: "lc07-b0-0123456789ab", Network: "lc07-b0-0123456789ab-net", Nonce: strings.Repeat("a", 64), Instance: targetInstance, Submission: targetSubmission, Expires: time.Now().UTC().Add(time.Hour), PGPort: 55432, NATSPort: 54222}
	original := ownershipDigest(m)
	for _, change := range []func(*marker){func(m *marker) { m.Expires = m.Expires.Add(time.Minute) }, func(m *marker) { m.PGPort++ }, func(m *marker) { m.NATSPort++ }} {
		changed := m
		change(&changed)
		if validate(changed) != nil || ownershipDigest(changed) == original {
			t.Fatal("changed expiry/endpoint reuses ownership digest")
		}
	}
	// Receipt must be checked before any database connection or owner RPC.
	receipt(t, dir, owner, original, m)
	raw, e := privateRead(filepath.Join(dir, owner+"-receipt.json"))
	if e != nil {
		t.Fatal("receipt not private")
	}
	var got map[string]any
	if json.Unmarshal(raw, &got) != nil || got["ownership_digest"] != original {
		t.Fatal("receipt binding")
	}
	checkReceipt(t, dir, owner, original, m)
	if validReceipt(raw, owner, strings.Repeat("b", 64), m) || validReceipt(append(raw, []byte(`{}`)...), owner, original, m) {
		t.Fatal("changed receipt admitted")
	}
	changed := m
	changed.Expires = changed.Expires.Add(time.Minute)
	if validReceipt(raw, owner, ownershipDigest(changed), changed) {
		t.Fatal("renewed authority reuses old receipt")
	}

}
