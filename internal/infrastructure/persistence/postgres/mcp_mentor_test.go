package repo

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Exercises the actual GORM repository and transaction/error/logging protocol.
// The controlled driver is not PostgreSQL or migration acceptance evidence.
type mentorOAuthSQLStep struct {
	fragments  []string
	columns    []string
	values     []driver.Value
	exec, inTx bool
	err        error
	check      func([]driver.NamedValue) bool
}
type mentorOAuthSQLFixture struct {
	steps                             []mentorOAuthSQLStep
	index, begins, commits, rollbacks int
	inTx                              bool
	bad                               bool
	commitErr                         error
}
type mentorOAuthSQLConnector struct{ fixture *mentorOAuthSQLFixture }

func (c mentorOAuthSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &mentorOAuthSQLConn{f: c.fixture}, nil
}
func (c mentorOAuthSQLConnector) Driver() driver.Driver { return mentorOAuthSQLDriver(c) }

type mentorOAuthSQLDriver struct{ fixture *mentorOAuthSQLFixture }

func (d mentorOAuthSQLDriver) Open(string) (driver.Conn, error) {
	return &mentorOAuthSQLConn{f: d.fixture}, nil
}

type mentorOAuthSQLConn struct{ f *mentorOAuthSQLFixture }

func (c *mentorOAuthSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *mentorOAuthSQLConn) Close() error { return nil }
func (c *mentorOAuthSQLConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *mentorOAuthSQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	if c.f.inTx {
		c.f.bad = true
		return nil, errors.New("nested transaction")
	}
	c.f.begins++
	c.f.inTx = true
	return mentorOAuthSQLTx{c.f}, nil
}

type mentorOAuthSQLTx struct{ f *mentorOAuthSQLFixture }

func (tx mentorOAuthSQLTx) Commit() error   { tx.f.commits++; tx.f.inTx = false; return tx.f.commitErr }
func (tx mentorOAuthSQLTx) Rollback() error { tx.f.rollbacks++; tx.f.inTx = false; return nil }
func (c *mentorOAuthSQLConn) step(query string, args []driver.NamedValue, exec bool) (mentorOAuthSQLStep, error) {
	if c.f.index >= len(c.f.steps) {
		c.f.bad = true
		return mentorOAuthSQLStep{}, errors.New("unexpected SQL")
	}
	step := c.f.steps[c.f.index]
	c.f.index++
	for _, fragment := range step.fragments {
		if !strings.Contains(query, fragment) {
			c.f.bad = true
			return step, errors.New("missing SQL constraint")
		}
	}
	if exec != step.exec || c.f.inTx != step.inTx || (step.check != nil && !step.check(args)) {
		c.f.bad = true
		return step, errors.New("wrong bound SQL transaction/input")
	}
	return step, step.err
}
func (c *mentorOAuthSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	step, err := c.step(query, args, false)
	if err != nil {
		return nil, err
	}
	return &mentorOAuthSQLRows{columns: step.columns, values: step.values}, nil
}
func (c *mentorOAuthSQLConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	_, err := c.step(query, args, true)
	if err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

type mentorOAuthSQLRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *mentorOAuthSQLRows) Columns() []string { return r.columns }
func (r *mentorOAuthSQLRows) Close() error      { return nil }
func (r *mentorOAuthSQLRows) Next(dst []driver.Value) error {
	if r.done || r.values == nil {
		return io.EOF
	}
	r.done = true
	copy(dst, r.values)
	return nil
}
func mentorOAuthSQLStore(t *testing.T, f *mentorOAuthSQLFixture) (domain.MCPMentorStore, *bytes.Buffer) {
	t.Helper()
	db := sql.OpenDB(mentorOAuthSQLConnector{f})
	t.Cleanup(func() { _ = db.Close() })
	captured := &bytes.Buffer{}
	baseLog := logger.New(log.New(captured, "", 0), logger.Config{LogLevel: logger.Info, Colorful: false})
	gdb, err := gorm.Open(postgres.New(postgres.Config{Conn: db, PreferSimpleProtocol: true}), &gorm.Config{DisableAutomaticPing: true, SkipDefaultTransaction: true, Logger: baseLog})
	if err != nil {
		t.Fatal(err)
	}
	store := NewMCPMentorStore(gdb)
	if gdb.Logger != baseLog {
		t.Fatal("owner logger mutated")
	}
	return store, captured
}
func mentorOAuthSQLGrant(now time.Time) (domain.MCPMentorConsent, domain.MCPMentorCode) {
	c := domain.MCPMentorConsent{ID: "20000000-0000-4000-8000-000000000001", MentorID: "10000000-0000-4000-8000-000000000001", ClientID: "mentor-client", Resource: "https://api.example.test/mcp", ExpiresAt: now.Add(time.Hour)}
	code := domain.MCPMentorCode{Hash: strings.Repeat("a", 64), MentorID: c.MentorID, ClientID: c.ClientID, ConsentID: c.ID, Resource: c.Resource, RedirectURI: "https://client.example.test/callback", Challenge: strings.Repeat("A", 43), ExpiresAt: now.Add(5 * time.Minute)}
	return c, code
}
func TestMCPMentorStoreConsentAndCodeCommitTogetherOrRollBackSilently(t *testing.T) {
	now := time.Now().UTC()
	consent, code := mentorOAuthSQLGrant(now)
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "code insert fails"}[fail], func(t *testing.T) {
			f := &mentorOAuthSQLFixture{steps: []mentorOAuthSQLStep{
				{fragments: []string{"public.auth_user", "FOR UPDATE", "email_verified=true", "signup.state<>'completed'"}, columns: []string{"id"}, values: []driver.Value{consent.MentorID}, inTx: true, check: func(args []driver.NamedValue) bool { return len(args) == 1 && args[0].Value == consent.MentorID }},
				{fragments: []string{"public.auth_mcp_mentor_client", "FOR SHARE", "disabled_at IS NULL", "ANY(redirect_uris)"}, columns: []string{"client_id"}, values: []driver.Value{consent.ClientID}, inTx: true},
				{fragments: []string{"UPDATE public.auth_mcp_mentor_consent", "revoked_at=clock_timestamp()"}, exec: true, inTx: true},
				{fragments: []string{"INSERT INTO public.auth_mcp_mentor_consent", "ARRAY['mentor:profile:read']"}, exec: true, inTx: true},
				{fragments: []string{"INSERT INTO public.auth_mcp_mentor_code", "pkce_challenge"}, exec: true, inTx: true, check: func(args []driver.NamedValue) bool {
					return len(args) == 8 && args[0].Value == code.Hash && args[1].Value == code.MentorID && args[3].Value == code.ConsentID && args[6].Value == code.Challenge
				}},
			}}
			if fail {
				f.steps[4].err = errors.New("sensitive driver statement material")
			}
			store, logs := mentorOAuthSQLStore(t, f)
			err := store.CreateGrant(context.Background(), consent, code, now)
			if f.bad || f.begins != 1 || f.index != 5 || logs.Len() != 0 {
				t.Fatal("unsafe transaction/logging protocol")
			}
			if fail {
				if err != domain.ErrMCPMentorUnavailable || f.rollbacks != 1 || f.commits != 0 {
					t.Fatal("partial consent commit or raw error exposed")
				}
			} else if err != nil || f.commits != 1 || f.rollbacks != 0 {
				t.Fatalf("commit failed: %v", err)
			}
		})
	}
}
func TestMCPMentorStoreAtomicConsumeBindingsAndActualColumnDecode(t *testing.T) {
	now := time.Now().UTC()
	consent, code := mentorOAuthSQLGrant(now)
	f := &mentorOAuthSQLFixture{steps: []mentorOAuthSQLStep{{fragments: []string{"UPDATE public.auth_mcp_mentor_code code SET consumed_at=clock_timestamp()", "code.consumed_at IS NULL", "consent.id=code.consent_id", "consent.mentor_id=code.mentor_id", "client.disabled_at IS NULL", "code.redirect_uri=ANY(client.redirect_uris)", "code.expires_at>clock_timestamp()", "consent.expires_at>clock_timestamp()", "account.email_verified=true", "RETURNING code.code_hash"}, columns: []string{"code_hash", "mentor_id", "client_id", "consent_id", "resource_uri", "redirect_uri", "pkce_challenge", "expires_at"}, values: []driver.Value{code.Hash, code.MentorID, code.ClientID, code.ConsentID, code.Resource, code.RedirectURI, code.Challenge, code.ExpiresAt}, check: func(args []driver.NamedValue) bool {
		return len(args) == 6 && args[0].Value == code.Hash && args[1].Value == code.ClientID && args[2].Value == code.RedirectURI && args[3].Value == code.Resource
	}}}}
	store, logs := mentorOAuthSQLStore(t, f)
	got, err := store.ConsumeCode(context.Background(), code.Hash, code.ClientID, code.RedirectURI, code.Resource, now)
	if err != nil || got == nil || *got != code || f.bad || f.index != 1 || f.begins != 0 || logs.Len() != 0 {
		t.Fatalf("atomic consume or column mapping mismatch: %+v %v", got, err)
	}
	_ = consent
}
func TestMCPMentorStoreDisconnectUsesSameAccountSerializationFence(t *testing.T) {
	now := time.Now().UTC()
	consent, _ := mentorOAuthSQLGrant(now)
	f := &mentorOAuthSQLFixture{steps: []mentorOAuthSQLStep{
		{fragments: []string{"public.auth_user", "FOR UPDATE"}, columns: []string{"id"}, values: []driver.Value{consent.MentorID}, inTx: true},
		{fragments: []string{"UPDATE public.auth_mcp_mentor_consent", "revoked_at IS NULL", "mentor_id=CAST($1 AS uuid)", "client_id=$2", "resource_uri=$3"}, exec: true, inTx: true},
	}}
	store, logs := mentorOAuthSQLStore(t, f)
	err := store.Revoke(context.Background(), consent.MentorID, consent.ClientID, consent.Resource)
	if err != nil || f.bad || f.commits != 1 || f.begins != 1 || logs.Len() != 0 {
		t.Fatal("disconnect escaped subject/transaction binding")
	}
}
