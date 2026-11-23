package repo

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
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

// This driver executes the real GORM repository over a controlled SQL transport.
// It is deliberately not a running PostgreSQL server or SQL acceptance.
const mentorSessionSQLLookupKey = "rt:55555555-5555-4555-8555-555555555555"

type mentorSessionSQLFixture struct {
	row      bool
	queryErr error
	calls    int
	query    string
	args     []driver.NamedValue
	after    func()
}
type mentorSessionSQLConnector struct{ fixture *mentorSessionSQLFixture }

func (c mentorSessionSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &mentorSessionSQLConn{fixture: c.fixture}, nil
}
func (c mentorSessionSQLConnector) Driver() driver.Driver {
	return mentorSessionSQLDriver{fixture: c.fixture}
}

type mentorSessionSQLDriver struct{ fixture *mentorSessionSQLFixture }

func (d mentorSessionSQLDriver) Open(string) (driver.Conn, error) {
	return &mentorSessionSQLConn{fixture: d.fixture}, nil
}

type mentorSessionSQLConn struct{ fixture *mentorSessionSQLFixture }

func (c *mentorSessionSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared statement")
}
func (c *mentorSessionSQLConn) Close() error { return nil }
func (c *mentorSessionSQLConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *mentorSessionSQLConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.fixture.calls++
	c.fixture.query = q
	c.fixture.args = append([]driver.NamedValue(nil), args...)
	if c.fixture.after != nil {
		c.fixture.after()
	}
	if c.fixture.queryErr != nil {
		return nil, c.fixture.queryErr
	}
	return &mentorSessionSQLRows{present: c.fixture.row}, nil
}

type mentorSessionSQLRows struct{ present, emitted bool }

func (*mentorSessionSQLRows) Columns() []string {
	return []string{"id", "user_id", "refresh_token_hash", "expires_at", "revoked_at"}
}
func (*mentorSessionSQLRows) Close() error { return nil }
func (r *mentorSessionSQLRows) Next(dest []driver.Value) error {
	if !r.present || r.emitted {
		return io.EOF
	}
	r.emitted = true
	copy(dest, []driver.Value{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", mentorSessionSQLLookupKey, time.Now().Add(time.Hour), nil})
	return nil
}

func mentorSessionSQLReader(t *testing.T, f *mentorSessionSQLFixture) domain.MentorSessionReader {
	t.Helper()
	db := sql.OpenDB(mentorSessionSQLConnector{fixture: f})
	t.Cleanup(func() { _ = db.Close() })
	gdb, err := gorm.Open(postgres.New(postgres.Config{Conn: db, PreferSimpleProtocol: true}), &gorm.Config{DisableAutomaticPing: true, SkipDefaultTransaction: true, Logger: logger.Discard})
	if err != nil {
		t.Fatal("SQL fixture construction failed")
	}
	r, err := NewMentorSessionReader(gdb)
	if err != nil || r == nil {
		t.Fatal("narrow persisted session reader unavailable")
	}
	return r
}

func TestMentorSessionReaderActualRepositoryAndMissingNormalization(t *testing.T) {
	f := &mentorSessionSQLFixture{row: true}
	r := mentorSessionSQLReader(t, f)
	got, err := r.FindActive(context.Background(), mentorSessionSQLLookupKey)
	if err != nil || got == nil || got.UserID != "22222222-2222-4222-8222-222222222222" || got.RefreshTokenHash != mentorSessionSQLLookupKey || f.calls != 1 {
		t.Fatal("actual existing active-session repository was not used")
	}
	for _, fragment := range []string{"auth_refresh_token", "refresh_token_hash", "revoked_at IS NULL", "expires_at >"} {
		if !strings.Contains(f.query, fragment) {
			t.Fatal("active-session query constraint missing")
		}
	}
	if len(f.args) < 2 || f.args[0].Value != mentorSessionSQLLookupKey {
		t.Fatal("hashed session lookup was not bound as parameter")
	}
	f.row = false
	got, err = r.FindActive(context.Background(), mentorSessionSQLLookupKey)
	if got != nil || err != domain.ErrNotFound || f.calls != 2 {
		t.Fatal("gorm record absence was not normalized")
	}
	f.queryErr = errors.New("sensitive query failure")
	got, err = r.FindActive(context.Background(), mentorSessionSQLLookupKey)
	if got != nil || err != domain.ErrMentorSessionUnavailable {
		t.Fatal("unknown persistence error was leaked or reclassified as absence")
	}
}

func TestMentorSessionReaderSuppressesOwnerSQLLogsWithoutChangingBaseLogger(t *testing.T) {
	for _, tc := range []struct {
		name       string
		row        bool
		driverErr  error
		wantResult bool
		wantErr    error
	}{
		{"active", true, nil, true, nil},
		{"absent", false, nil, false, domain.ErrNotFound},
		{"outage", false, errors.New("synthetic sensitive driver diagnostic"), false, domain.ErrMentorSessionUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &mentorSessionSQLFixture{row: tc.row, queryErr: tc.driverErr}
			db := sql.OpenDB(mentorSessionSQLConnector{fixture: f})
			t.Cleanup(func() { _ = db.Close() })
			var captured bytes.Buffer
			baseLogger := logger.New(log.New(&captured, "", 0), logger.Config{LogLevel: logger.Info, Colorful: false})
			gdb, err := gorm.Open(postgres.New(postgres.Config{Conn: db, PreferSimpleProtocol: true}), &gorm.Config{DisableAutomaticPing: true, SkipDefaultTransaction: true, Logger: baseLogger})
			if err != nil {
				t.Fatal("capturing owner SQL fixture construction failed")
			}
			r, err := NewMentorSessionReader(gdb)
			if err != nil || r == nil || gdb.Logger != baseLogger {
				t.Fatal("new reader unavailable or changed original logger")
			}
			got, err := r.FindActive(context.Background(), mentorSessionSQLLookupKey)
			if (got != nil) != tc.wantResult || err != tc.wantErr || f.calls != 1 {
				t.Fatal("log suppression changed session authority behavior")
			}
			if captured.Len() != 0 || gdb.Logger != baseLogger {
				t.Fatal("strict session boundary logged SQL/session data or changed base logger")
			}
			// The logger must be genuinely active for legacy callers, not replaced
			// globally or disabled by the fixture to hide the confidentiality path.
			_, _ = NewRefreshTokenRepository(gdb).FindActive(context.Background(), mentorSessionSQLLookupKey)
			if !strings.Contains(captured.String(), mentorSessionSQLLookupKey) || f.calls != 2 ||
				(tc.driverErr != nil && !strings.Contains(captured.String(), tc.driverErr.Error())) {
				t.Fatal("original owner logger was not retained and exercised")
			}
		})
	}
}

type mentorSessionResultFixture struct {
	result *domain.RefreshToken
	err    error
	calls  int
}

func (f *mentorSessionResultFixture) FindActive(context.Context, string) (*domain.RefreshToken, error) {
	f.calls++
	return f.result, f.err
}

func TestMentorSessionReaderConfigurationAndErrorClassification(t *testing.T) {
	for _, db := range []*gorm.DB{nil, {}} {
		if got, err := NewMentorSessionReader(db); got != nil || err != domain.ErrMentorSessionUnavailable {
			t.Fatal("unconfigured database admitted")
		}
	}
	for _, r := range []*mentorSessionReader{nil, {}} {
		if got, err := r.FindActive(context.Background(), mentorSessionSQLLookupKey); got != nil || err != domain.ErrMentorSessionUnavailable {
			t.Fatal("zero session adapter admitted")
		}
	}
	for _, tc := range []struct {
		name      string
		err, want error
	}{{"gorm missing", gorm.ErrRecordNotFound, domain.ErrNotFound}, {"wrapped known missing", fmt.Errorf("lookup: %w", gorm.ErrRecordNotFound), domain.ErrNotFound}, {"domain missing", domain.ErrNotFound, domain.ErrNotFound}, {"mixed missing", errors.Join(gorm.ErrRecordNotFound, errors.New("outage")), domain.ErrMentorSessionUnavailable}, {"unknown", errors.New("sensitive driver detail"), domain.ErrMentorSessionUnavailable}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &mentorSessionResultFixture{err: tc.err}
			r := &mentorSessionReader{source: f}
			got, err := r.FindActive(context.Background(), mentorSessionSQLLookupKey)
			if got != nil || err != tc.want || f.calls != 1 {
				t.Fatal("known absence/unknown failure not distinguished safely")
			}
		})
	}
	f := &mentorSessionResultFixture{}
	r := &mentorSessionReader{source: f}
	if got, err := r.FindActive(context.Background(), mentorSessionSQLLookupKey); got != nil || err != domain.ErrMentorSessionUnavailable {
		t.Fatal("nil successful row admitted")
	}
}

func TestMentorSessionReaderInputAndCancellation(t *testing.T) {
	f := &mentorSessionSQLFixture{row: true}
	r := mentorSessionSQLReader(t, f)
	for _, hash := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		if got, err := r.FindActive(context.Background(), hash); got != nil || err != domain.ErrMentorSessionUnavailable || f.calls != 0 {
			t.Fatal("invalid hash reached SQL reader")
		}
	}
	if got, err := r.FindActive(nil, mentorSessionSQLLookupKey); got != nil || err != domain.ErrMentorSessionUnavailable || f.calls != 0 {
		t.Fatal("nil context reached SQL reader")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := r.FindActive(ctx, mentorSessionSQLLookupKey); got != nil || err != domain.ErrMentorSessionUnavailable || f.calls != 0 {
		t.Fatal("cancelled read reached SQL")
	}
	ctx, cancel = context.WithCancel(context.Background())
	f.after = cancel
	if got, err := r.FindActive(ctx, mentorSessionSQLLookupKey); got != nil || err != domain.ErrMentorSessionUnavailable {
		t.Fatal("cancelled SQL result became authority")
	}
}
