package repo

import (
	"context"
	"errors"
	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"time"
)

func (r *authUserRepo) ResetPassword(ctx context.Context, email, hash string, now time.Time) error {
	return r.db.WithContext(ctx).Session(&gorm.Session{Logger: logger.Discard}).Transaction(func(tx *gorm.DB) error {
		var u domain.AuthUser
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("email = ?", email).First(&u).Error; err != nil {
			return err
		}
		if u.PasswordHash == nil {
			return errors.New("local credential required")
		}
		if err := tx.Model(&u).Updates(map[string]interface{}{"password_hash": hash, "password_updated_at": now}).Error; err != nil {
			return err
		}
		return tx.Model(&domain.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", u.ID).Update("revoked_at", now).Error
	})
}
