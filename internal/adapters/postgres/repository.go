package repo

import (
	"context"
	"time"

	"gorm.io/gorm"

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
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *domain.RefreshToken) error
	FindActive(ctx context.Context, hash string) (*domain.RefreshToken, error)
	RevokeByHash(ctx context.Context, hash string) error
}

type authUserRepo struct{ db *gorm.DB }

type authIdentityRepo struct{ db *gorm.DB }

type refreshTokenRepo struct{ db *gorm.DB }

func NewAuthUserRepository(db *gorm.DB) AuthUserRepository { return &authUserRepo{db: db} }
func NewAuthIdentityRepository(db *gorm.DB) AuthIdentityRepository { return &authIdentityRepo{db: db} }
func NewRefreshTokenRepository(db *gorm.DB) RefreshTokenRepository { return &refreshTokenRepo{db: db} }

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
