package repo

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/example/auth-service/internal/domain"
)

type AuthUserRepository interface {
	Create(ctx context.Context, user *domain.AuthUser) error
	FindByEmail(ctx context.Context, email string) (*domain.AuthUser, error)
	FindByID(ctx context.Context, id string) (*domain.AuthUser, error)
	Update(ctx context.Context, user *domain.AuthUser) error
}

type AuthIdentityRepository interface {
	FindByProvider(ctx context.Context, provider, providerUserID string) (*domain.AuthIdentity, error)
	Create(ctx context.Context, identity *domain.AuthIdentity) error
	ResolveUser(ctx context.Context, identity *domain.AuthIdentity) (*domain.AuthUser, bool, error)
	ListByUser(ctx context.Context, userID string) ([]domain.AuthIdentity, error)
	Delete(ctx context.Context, userID, provider, providerUserID string) error
}

type OAuthTransactionRepository interface {
	Create(ctx context.Context, transaction *domain.OAuthTransaction) error
	Consume(ctx context.Context, stateHash, provider string, now time.Time) (*domain.OAuthTransaction, error)
	DeleteExpired(ctx context.Context, now time.Time) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *domain.RefreshToken) error
	FindActive(ctx context.Context, hash string) (*domain.RefreshToken, error)
	RevokeByHash(ctx context.Context, hash string) error
}

type authUserRepo struct{ db *gorm.DB }

type authIdentityRepo struct{ db *gorm.DB }

type refreshTokenRepo struct{ db *gorm.DB }

type oauthTransactionRepo struct{ db *gorm.DB }

func NewAuthUserRepository(db *gorm.DB) AuthUserRepository         { return &authUserRepo{db: db} }
func NewAuthIdentityRepository(db *gorm.DB) AuthIdentityRepository { return &authIdentityRepo{db: db} }
func NewRefreshTokenRepository(db *gorm.DB) RefreshTokenRepository { return &refreshTokenRepo{db: db} }
func NewOAuthTransactionRepository(db *gorm.DB) OAuthTransactionRepository {
	return &oauthTransactionRepo{db: db}
}

func (r *authUserRepo) Create(ctx context.Context, user *domain.AuthUser) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *authUserRepo) FindByEmail(ctx context.Context, email string) (*domain.AuthUser, error) {
	var user domain.AuthUser
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *authUserRepo) FindByID(ctx context.Context, id string) (*domain.AuthUser, error) {
	var user domain.AuthUser
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *authUserRepo) Update(ctx context.Context, user *domain.AuthUser) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *authIdentityRepo) FindByProvider(ctx context.Context, provider, providerUserID string) (*domain.AuthIdentity, error) {
	var identity domain.AuthIdentity
	if err := r.db.WithContext(ctx).Where("provider = ? AND provider_user_id = ?", provider, providerUserID).First(&identity).Error; err != nil {
		return nil, err
	}
	return &identity, nil
}

func (r *authIdentityRepo) Create(ctx context.Context, identity *domain.AuthIdentity) error {
	return r.db.WithContext(ctx).Create(identity).Error
}

func (r *authIdentityRepo) ResolveUser(ctx context.Context, identity *domain.AuthIdentity) (*domain.AuthUser, bool, error) {
	var user *domain.AuthUser
	created := false
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existingIdentity domain.AuthIdentity
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("provider = ? AND provider_user_id = ?", identity.Provider, identity.ProviderUserID).
			First(&existingIdentity).Error
		if err == nil {
			var existingUser domain.AuthUser
			if err := tx.First(&existingUser, "id = ?", existingIdentity.UserID).Error; err != nil {
				return err
			}
			if err := tx.Model(&existingIdentity).Updates(map[string]interface{}{
				"email":       identity.Email,
				"raw_profile": identity.RawProfile,
			}).Error; err != nil {
				return err
			}
			user = &existingUser
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		// Serialize first-time identity linking for the same normalized email.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", identity.Email).Error; err != nil {
			return err
		}
		var resolved domain.AuthUser
		err = tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("email = ?", identity.Email).First(&resolved).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			resolved = domain.AuthUser{Email: identity.Email}
			if err := tx.Create(&resolved).Error; err != nil {
				return err
			}
			created = true
		} else if err != nil {
			return err
		}

		identity.UserID = resolved.ID
		if err := tx.Create(identity).Error; err != nil {
			return err
		}
		user = &resolved
		return nil
	})
	return user, created, err
}

func (r *authIdentityRepo) ListByUser(ctx context.Context, userID string) ([]domain.AuthIdentity, error) {
	var identities []domain.AuthIdentity
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

func (r *authIdentityRepo) Delete(ctx context.Context, userID, provider, providerUserID string) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ? AND provider_user_id = ?", userID, provider, providerUserID).
		Delete(&domain.AuthIdentity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *refreshTokenRepo) Create(ctx context.Context, token *domain.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *refreshTokenRepo) FindActive(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	var token domain.RefreshToken
	if err := r.db.WithContext(ctx).
		Where("refresh_token_hash = ? AND (revoked_at IS NULL) AND expires_at > ?", hash, time.Now()).
		First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *refreshTokenRepo) RevokeByHash(ctx context.Context, hash string) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("refresh_token_hash = ?", hash).
		Updates(map[string]interface{}{"revoked_at": &now}).Error
}

func (r *oauthTransactionRepo) Create(ctx context.Context, transaction *domain.OAuthTransaction) error {
	return r.db.WithContext(ctx).Create(transaction).Error
}

func (r *oauthTransactionRepo) Consume(ctx context.Context, stateHash, provider string, now time.Time) (*domain.OAuthTransaction, error) {
	var transaction domain.OAuthTransaction
	result := r.db.WithContext(ctx).Raw(`
		UPDATE auth_oauth_transaction
		SET consumed_at = ?
		WHERE state_hash = ?
		  AND provider = ?
		  AND consumed_at IS NULL
		  AND expires_at > ?
		RETURNING *
	`, now, stateHash, provider, now).Scan(&transaction)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 || transaction.ID == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &transaction, nil
}

func (r *oauthTransactionRepo) DeleteExpired(ctx context.Context, now time.Time) error {
	return r.db.WithContext(ctx).
		Where("expires_at <= ? OR consumed_at IS NOT NULL", now).
		Delete(&domain.OAuthTransaction{}).Error
}
