package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Explicitly opt in only on the dedicated, network-isolated restore database.
func TestLC08AtomicRefreshPostgres(t *testing.T) {
	dsn := os.Getenv("LC08_AUTH_ATOMIC_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated LC08 auth test database required")
	}
	if !strings.Contains(dsn, "host=/var/run/postgresql") || !strings.Contains(dsn, "dbname=lc08_auth_atomic_20261028_test") {
		t.Fatal("unsafe test DSN")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	var dbName string
	var unixSocket bool
	if err = db.Raw("SELECT current_database(), inet_server_addr() IS NULL").Row().Scan(&dbName, &unixSocket); err != nil || dbName != "lc08_auth_atomic_20261028_test" || !unixSocket {
		t.Fatal("isolated socket/database guard")
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	ctx := context.Background()
	repo := NewRefreshTokenRepository(db)
	freshUser := func() string {
		id := t16RepoUUID(t)
		if e := db.Exec("INSERT INTO auth_user (id,email,password_hash) VALUES (?,?,?)", id, id+"@isolated.invalid", "test-only").Error; e != nil {
			t.Fatal(e)
		}
		return id
	}
	add := func(user, hash string, expires time.Time) {
		if e := repo.Create(ctx, &domain.RefreshToken{UserID: user, RefreshTokenHash: hash, ExpiresAt: expires}); e != nil {
			t.Fatal(e)
		}
	}
	active := func(user string) int64 {
		var n int64
		if e := db.Model(&domain.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL AND expires_at > now()", user).Count(&n).Error; e != nil {
			t.Fatal(e)
		}
		return n
	}
	t.Run("concurrent_refresh_replay_and_lost_response", func(t *testing.T) {
		u := freshUser()
		old := "old-" + u
		add(u, old, time.Now().Add(time.Hour))
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs <- repo.Rotate(ctx, old, u, &domain.RefreshToken{UserID: u, RefreshTokenHash: fmt.Sprintf("%s-%d", u, i), ExpiresAt: time.Now().Add(time.Hour)})
			}(i)
		}
		wg.Wait()
		close(errs)
		success := 0
		for e := range errs {
			if e == nil {
				success++
			} else if !errors.Is(e, domain.ErrNotFound) {
				t.Fatalf("unexpected error: %v", e)
			}
		}
		if success != 1 || active(u) != 1 {
			t.Fatalf("success=%d active=%d", success, active(u))
		}
		// A committed rotation with a lost HTTP response has the same server state:
		// the consumed token must never be reaccepted, requiring reauthentication.
		e := repo.Rotate(ctx, old, u, &domain.RefreshToken{UserID: u, RefreshTokenHash: "replay-" + u, ExpiresAt: time.Now().Add(time.Hour)})
		if !errors.Is(e, domain.ErrNotFound) || active(u) != 1 {
			t.Fatal("replay accepted or sessions multiplied")
		}
	})
	t.Run("insert_failure_rolls_back_consumption", func(t *testing.T) {
		u := freshUser()
		old := "old-" + u
		add(u, old, time.Now().Add(time.Hour))
		e := repo.Rotate(ctx, old, u, &domain.RefreshToken{ID: "not-a-uuid", UserID: u, RefreshTokenHash: "invalid-" + u, ExpiresAt: time.Now().Add(time.Hour)})
		if e == nil {
			t.Fatal("expected insert error")
		}
		if _, e = repo.FindActive(ctx, old); e != nil || active(u) != 1 {
			t.Fatal("failed insert consumed old session")
		}
	})
	t.Run("commit_failure_rolls_back_consumption", func(t *testing.T) {
		// Fault injection is confined to the dedicated isolated test DB. A
		// deferred unique violation is reported only when the transaction commits.
		var exists bool
		if e := db.Raw("SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lc08_test_deferred_hash_unique')").Scan(&exists).Error; e != nil {
			t.Fatal(e)
		}
		if !exists {
			if e := db.Exec("ALTER TABLE auth_refresh_token ADD CONSTRAINT lc08_test_deferred_hash_unique UNIQUE (refresh_token_hash) DEFERRABLE INITIALLY DEFERRED").Error; e != nil {
				t.Fatal(e)
			}
		}
		u := freshUser()
		old := "old-" + u
		add(u, old, time.Now().Add(time.Hour))
		other := freshUser()
		conflict := "conflict-" + other
		add(other, conflict, time.Now().Add(time.Hour))
		e := repo.Rotate(ctx, old, u, &domain.RefreshToken{UserID: u, RefreshTokenHash: conflict, ExpiresAt: time.Now().Add(time.Hour)})
		if e == nil {
			t.Fatal("expected deferred commit failure")
		}
		if _, e = repo.FindActive(ctx, old); e != nil || active(u) != 1 {
			t.Fatal("failed commit consumed old session")
		}
	})
	t.Run("expired_and_revoked", func(t *testing.T) {
		u := freshUser()
		expired := "expired-" + u
		add(u, expired, time.Now().Add(-time.Second))
		if e := repo.Rotate(ctx, expired, u, &domain.RefreshToken{UserID: u, RefreshTokenHash: "new-" + u, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(e, domain.ErrNotFound) {
			t.Fatal("expired accepted")
		}
		revoked := "revoked-" + u
		add(u, revoked, time.Now().Add(time.Hour))
		if e := repo.RevokeByHash(ctx, revoked); e != nil {
			t.Fatal(e)
		}
		if e := repo.Rotate(ctx, revoked, u, &domain.RefreshToken{UserID: u, RefreshTokenHash: "other-" + u, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(e, domain.ErrNotFound) {
			t.Fatal("revoked accepted")
		}
	})
	t.Run("password_reset_and_refresh_never_leave_active_session", func(t *testing.T) {
		reset := NewAuthUserRepository(db).(interface {
			ResetPassword(context.Context, string, string, time.Time) error
		})
		for i := 0; i < 12; i++ {
			u := freshUser()
			old := "reset-race-" + u
			add(u, old, time.Now().Add(time.Hour))
			start := make(chan struct{})
			var wg sync.WaitGroup
			var rotateErr, resetErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				rotateErr = repo.Rotate(ctx, old, u, &domain.RefreshToken{UserID: u, RefreshTokenHash: "reset-new-" + u, ExpiresAt: time.Now().Add(time.Hour)})
			}()
			go func() {
				defer wg.Done()
				<-start
				resetErr = reset.ResetPassword(ctx, u+"@isolated.invalid", "new-test-only-hash", time.Now())
			}()
			close(start)
			wg.Wait()
			if resetErr != nil || (rotateErr != nil && !errors.Is(rotateErr, domain.ErrNotFound)) || active(u) != 0 {
				t.Fatalf("reset/refresh race failed: rotate=%v reset=%v active=%d", rotateErr, resetErr, active(u))
			}
		}
	})
	t.Run("logout_refresh_race_never_duplicates", func(t *testing.T) {
		for i := 0; i < 16; i++ {
			u := freshUser()
			old := "race-" + u
			add(u, old, time.Now().Add(time.Hour))
			start := make(chan struct{})
			var wg sync.WaitGroup
			var rotateErr, logoutErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				rotateErr = repo.Rotate(ctx, old, u, &domain.RefreshToken{UserID: u, RefreshTokenHash: "new-" + u, ExpiresAt: time.Now().Add(time.Hour)})
			}()
			go func() { defer wg.Done(); <-start; logoutErr = repo.RevokeByHash(ctx, old) }()
			close(start)
			wg.Wait()
			switch {
			case logoutErr == nil && errors.Is(rotateErr, domain.ErrNotFound):
				if active(u) != 0 {
					t.Fatal("successful logout left an active replacement")
				}
			case rotateErr == nil && errors.Is(logoutErr, domain.ErrNotFound):
				if active(u) != 1 {
					t.Fatal("successful refresh did not preserve exactly one replacement")
				}
			default:
				t.Fatalf("logout/refresh results are not mutually exclusive: refresh=%v logout=%v", rotateErr, logoutErr)
			}
		}
	})
}
