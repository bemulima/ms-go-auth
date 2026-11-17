package domain

import (
	"context"
	"time"
)

// NotificationRecipientRecord is an atomic Auth projection. It deliberately
// contains no credentials, OAuth identities, session or profile information.
type NotificationRecipientRecord struct {
	UserID        string
	Email         string
	Verified      bool
	SignupPending bool
	UpdatedAt     time.Time
}

type NotificationRecipientReader interface {
	ReadNotificationRecipient(context.Context, string) (NotificationRecipientRecord, error)
}
