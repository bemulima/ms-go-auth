package repo

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
)

type C2BBootstrapRepository struct{ DB *gorm.DB }

func c2bAuthDatabase(tx *gorm.DB) error {
	var db, user string
	if e := tx.Raw("SELECT current_database(),current_user").Row().Scan(&db, &user); e != nil {
		return e
	}
	if db != "c2b_auth_20261016" || user != "c2b_auth_fixture" {
		return errors.New("isolated bootstrap database denied")
	}
	return nil
}
func (r C2BBootstrapRepository) SaveC2BIntent(ctx context.Context, i domain.C2BIntent, s domain.C2BSignedIntent) error {
	if !i.Valid() {
		return errors.New("invalid intent")
	}
	raw, _ := json.Marshal(s)
	return r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := c2bAuthDatabase(tx); e != nil {
			return e
		}
		if e := tx.Exec("INSERT INTO c2b_auth_bootstrap_intent(operation_id,principal_id,intent_digest,signed_json) VALUES(?,?,?,?::jsonb) ON CONFLICT(operation_id) DO NOTHING", i.Operation, i.Principal, i.Digest(), raw).Error; e != nil {
			return e
		}
		var digest string
		var stored []byte
		if e := tx.Raw("SELECT intent_digest,signed_json FROM c2b_auth_bootstrap_intent WHERE operation_id=?", i.Operation).Row().Scan(&digest, &stored); e != nil {
			return e
		}
		var old domain.C2BSignedIntent
		if json.Unmarshal(stored, &old) != nil || digest != i.Digest() || old != s {
			return errors.New("immutable intent conflict")
		}
		return nil
	})
}
func (r C2BBootstrapRepository) LoadC2BIntent(ctx context.Context, id string) (domain.C2BSignedIntent, error) {
	var s domain.C2BSignedIntent
	var b []byte
	e := r.DB.WithContext(ctx).Raw("SELECT signed_json FROM c2b_auth_bootstrap_intent WHERE operation_id=?", id).Row().Scan(&b)
	if e == nil {
		e = json.Unmarshal(b, &s)
	}
	return s, e
}
func (r C2BBootstrapRepository) FinalizeC2B(ctx context.Context, i domain.C2BIntent, receipt domain.C2BReceipt, u *domain.AuthUser) (*domain.AuthUser, error) {
	var result domain.AuthUser
	if !i.Valid() || !receipt.Valid() || receipt.Intent != i {
		return nil, errors.New("invalid bootstrap binding")
	}
	raw, _ := json.Marshal(receipt)
	e := r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := c2bAuthDatabase(tx); e != nil {
			return e
		}
		if e := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", "c2b-auth:"+i.Principal).Error; e != nil {
			return e
		}
		var digest string
		if e := tx.Raw("SELECT intent_digest FROM c2b_auth_bootstrap_intent WHERE operation_id=?", i.Operation).Row().Scan(&digest); e != nil || digest != i.Digest() {
			return errors.New("missing exact prepared intent")
		}
		var old []byte
		err := tx.Raw("SELECT receipt_json FROM c2b_auth_bootstrap_audit WHERE operation_id=?", i.Operation).Row().Scan(&old)
		if err == nil {
			var x domain.C2BReceipt
			if json.Unmarshal(old, &x) != nil || x != receipt {
				return errors.New("bootstrap receipt conflict")
			}
			return tx.First(&result, "id = ? AND email = ?", i.Principal, i.Email).Error
		}
		var count int64
		if e := tx.Model(&domain.AuthUser{}).Where("id = ? OR lower(email) = ?", i.Principal, i.Email).Count(&count).Error; e != nil {
			return e
		}
		if count != 0 {
			return errors.New("existing identity cannot be adopted")
		}
		if e := tx.Create(u).Error; e != nil {
			return e
		}
		if e := tx.Exec("INSERT INTO c2b_auth_bootstrap_audit(operation_id,principal_id,receipt_json) VALUES(?,?,?::jsonb)", i.Operation, i.Principal, raw).Error; e != nil {
			return e
		}
		result = *u
		return nil
	})
	return &result, e
}
func (r *authUserRepo) C2BMentorEligible(ctx context.Context, id string) (bool, error) {
	if id != domain.C2BMentorID {
		return false, nil
	}
	var raw []byte
	e := r.db.WithContext(ctx).Raw("SELECT a.receipt_json FROM c2b_auth_bootstrap_audit a JOIN auth_user u ON u.id=a.principal_id WHERE u.id=? AND u.email=? AND u.email_verified=true", id, "mentor+"+domain.C2BRun+"@verification.invalid").Row().Scan(&raw)
	if e != nil {
		return false, e
	}
	var receipt domain.C2BReceipt
	if json.Unmarshal(raw, &receipt) != nil {
		return false, errors.New("invalid mentor audit")
	}
	return receipt.Valid() && receipt.Intent.Principal == id && receipt.Intent.Role == "mentor", nil
}
