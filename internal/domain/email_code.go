package domain

import (
	"context"
	"time"
)

// Mailer is an outbound delivery port. Codes are never returned by public APIs.
type Mailer interface {
	Send(context.Context, string, string, string) error
}

// PasswordResetRepository commits the credential change and session revocation together.
type PasswordResetRepository interface {
	ResetPassword(context.Context, string, string, time.Time) error
}
