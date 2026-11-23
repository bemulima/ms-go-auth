package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
)

type notificationRecipientReader struct {
	rows  []domain.NotificationRecipientRecord
	calls int
	err   error
}

func (r *notificationRecipientReader) ReadNotificationRecipient(ctx context.Context, id string) (domain.NotificationRecipientRecord, error) {
	r.calls++
	if r.err != nil {
		return domain.NotificationRecipientRecord{}, r.err
	}
	if err := ctx.Err(); err != nil {
		return domain.NotificationRecipientRecord{}, err
	}
	i := r.calls - 1
	if i >= len(r.rows) {
		i = len(r.rows) - 1
	}
	return r.rows[i], nil
}
func TestNotificationRecipientCurrentVerifiedOwner(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	row := domain.NotificationRecipientRecord{UserID: "11111111-1111-4111-8111-111111111111", Email: "student@example.com", Verified: true, UpdatedAt: now.Add(-time.Hour)}
	cases := []struct {
		name   string
		change func(*domain.NotificationRecipientRecord)
		deny   bool
	}{
		{"verified", func(*domain.NotificationRecipientRecord) {}, false},
		{"revoked", func(r *domain.NotificationRecipientRecord) { r.Verified = false }, true},
		{"pending", func(r *domain.NotificationRecipientRecord) { r.SignupPending = true }, true},
		{"email changed", func(r *domain.NotificationRecipientRecord) { r.Email = "replacement@example.com" }, true},
		{"revision changed", func(r *domain.NotificationRecipientRecord) { r.UpdatedAt = now }, true},
		{"wrong identity", func(r *domain.NotificationRecipientRecord) { r.UserID = "22222222-2222-4222-8222-222222222222" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := row
			tc.change(&next)
			reader := &notificationRecipientReader{rows: []domain.NotificationRecipientRecord{row, next}}
			s := NotificationRecipientService{Reader: reader, Now: func() time.Time { return now }}
			got, err := s.Resolve(context.Background(), row.UserID)
			if tc.deny {
				if !errors.Is(err, ErrNotificationRecipientDenied) {
					t.Fatalf("current owner denial required: %#v %v", got, err)
				}
				return
			}
			if err != nil || got.UserID != row.UserID || got.Email != row.Email || !got.Verified || len(got.Revision) != 64 || !got.CheckedAt.Equal(now) || reader.calls != 2 {
				t.Fatalf("projection: %#v %v calls=%d", got, err, reader.calls)
			}
		})
	}
}

func TestNotificationRecipientInvalidAndUnavailable(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	row := domain.NotificationRecipientRecord{UserID: "11111111-1111-4111-8111-111111111111", Email: "student@example.com", Verified: true, UpdatedAt: now.Add(-time.Hour)}
	for _, email := range []string{"Name <student@example.com>", "student@example.com\r\nBcc: x@evil.com", "masked@***", ""} {
		bad := row
		bad.Email = email
		r := &notificationRecipientReader{rows: []domain.NotificationRecipientRecord{bad}}
		s := NotificationRecipientService{Reader: r, Now: func() time.Time { return now }}
		if _, e := s.Resolve(context.Background(), row.UserID); !errors.Is(e, ErrNotificationRecipientDenied) {
			t.Fatalf("malformed endpoint accepted %q: %v", email, e)
		}
	}
	reader := &notificationRecipientReader{err: errors.New("private DB detail")}
	s := NotificationRecipientService{Reader: reader, Now: func() time.Time { return now }}
	if _, err := s.Resolve(context.Background(), row.UserID); !errors.Is(err, ErrNotificationRecipientUnavailable) {
		t.Fatal(err)
	}
	if _, err := s.Resolve(context.Background(), "foreign"); !errors.Is(err, ErrNotificationRecipientInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Resolve(ctx, row.UserID); !errors.Is(err, ErrNotificationRecipientUnavailable) {
		t.Fatal(err)
	}
}
