package repo

import (
	"context"
	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
)

type notificationRecipientReader struct{ db *gorm.DB }

func NewNotificationRecipientReader(db *gorm.DB) domain.NotificationRecipientReader {
	return &notificationRecipientReader{db: db}
}

// The credential projection and pending-signup gate are read in one statement.
// No password, identity, refresh session or profile columns are selected.
func (r *notificationRecipientReader) ReadNotificationRecipient(ctx context.Context, id string) (domain.NotificationRecipientRecord, error) {
	var row domain.NotificationRecipientRecord
	if r == nil || r.db == nil {
		return row, gorm.ErrInvalidDB
	}
	result := r.db.WithContext(ctx).Raw(`SELECT u.id AS user_id,u.email,u.email_verified AS verified,u.updated_at,EXISTS(SELECT 1 FROM auth_signup_completion s WHERE s.principal_id=u.id AND s.state<>'completed') AS signup_pending FROM auth_user u WHERE u.id=? LIMIT 1`, id).Scan(&row)
	if result.Error != nil {
		return domain.NotificationRecipientRecord{}, result.Error
	}
	if result.RowsAffected != 1 {
		return domain.NotificationRecipientRecord{}, domain.ErrNotFound
	}
	return row, nil
}
