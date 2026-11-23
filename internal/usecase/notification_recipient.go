package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
)

var (
	ErrNotificationRecipientInvalid     = errors.New("invalid notification recipient request")
	ErrNotificationRecipientDenied      = errors.New("notification recipient unavailable")
	ErrNotificationRecipientUnavailable = errors.New("notification recipient dependency unavailable")
)

type NotificationRecipient struct {
	Schema    string    `json:"schema"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Verified  bool      `json:"verified"`
	Revision  string    `json:"revision"`
	CheckedAt time.Time `json:"checked_at"`
}

type NotificationRecipientService struct {
	Reader domain.NotificationRecipientReader
	Now    func() time.Time
}

// Resolve observes the current verified address, including the incomplete
// signup gate, twice. CheckedAt records this observation, not the historical
// verification time (Auth does not store that timestamp).
func (s NotificationRecipientService) Resolve(ctx context.Context, id string) (NotificationRecipient, error) {
	if !notificationRecipientUUID(id) {
		return NotificationRecipient{}, ErrNotificationRecipientInvalid
	}
	if s.Reader == nil || s.Now == nil || ctx.Err() != nil {
		return NotificationRecipient{}, ErrNotificationRecipientUnavailable
	}
	before, err := s.Reader.ReadNotificationRecipient(ctx, id)
	if err != nil {
		return NotificationRecipient{}, notificationRecipientError(err)
	}
	if !validNotificationRecipient(before, id) {
		return NotificationRecipient{}, ErrNotificationRecipientDenied
	}
	current, err := s.Reader.ReadNotificationRecipient(ctx, id)
	if err != nil {
		return NotificationRecipient{}, notificationRecipientError(err)
	}
	if ctx.Err() != nil {
		return NotificationRecipient{}, ErrNotificationRecipientUnavailable
	}
	if !validNotificationRecipient(current, id) || before != current {
		return NotificationRecipient{}, ErrNotificationRecipientDenied
	}
	now := s.Now().UTC()
	if now.IsZero() || now.Year() < 2000 || now.Year() > 2100 || current.UpdatedAt.After(now) {
		return NotificationRecipient{}, ErrNotificationRecipientUnavailable
	}
	digest := sha256.Sum256([]byte("auth.notification-recipient.v1\n" + id + "\n" + current.Email + "\n" + current.UpdatedAt.UTC().Format(time.RFC3339Nano)))
	return NotificationRecipient{Schema: "auth.notification-recipient.v1", UserID: id, Email: current.Email, Verified: true, Revision: hex.EncodeToString(digest[:]), CheckedAt: now}, nil
}
func notificationRecipientError(err error) error {
	if errors.Is(err, domain.ErrNotFound) {
		return ErrNotificationRecipientDenied
	}
	return ErrNotificationRecipientUnavailable
}
func validNotificationRecipient(r domain.NotificationRecipientRecord, id string) bool {
	if r.UserID != id || !r.Verified || r.SignupPending || r.UpdatedAt.IsZero() || len(r.Email) > 254 || strings.ContainsAny(r.Email, "\r\n\x00\t ") {
		return false
	}
	parsed, err := mail.ParseAddress(r.Email)
	if err != nil || parsed.Address != r.Email || parsed.Name != "" {
		return false
	}
	local, host, ok := strings.Cut(r.Email, "@")
	if !ok || local == "" || !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
func notificationRecipientUUID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
