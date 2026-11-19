package repo

import (
	"context"
	"errors"
	"time"

	"github.com/example/auth-service/internal/domain"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// NewCAT49ReviewerOperatorRepository is only consumed by the task-owned CLI.
func NewCAT49ReviewerOperatorRepository(db *gorm.DB) domain.CAT49ReviewerOperatorStore {
	return &authUserRepo{db:db}
}

// RegisterCAT49Reviewer never updates an existing principal. The Auth user and
// append-only pending receipt are committed in the same owner transaction.
func (r *authUserRepo) RegisterCAT49Reviewer(ctx context.Context, input domain.CAT49ReviewerRegistration) (bool,error) {
	created:=false
	err:=r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var identity struct { Database string; Operator string; Super bool }
		if e:=tx.Raw("SELECT current_database() AS database, current_user AS operator, (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS super").Scan(&identity).Error;e!=nil{return e}
		if identity.Database!=input.Receipt.AuthDatabase || identity.Super || identity.Operator=="" {
			return errors.New("CAT49 wrong Auth owner database")
		}
		if e:=tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?,0))","cat49-auth-reviewer:"+input.Receipt.RunID).Error;e!=nil{return e}
		var old []struct {
			RequestID string
			PrincipalID string
			RunID string
			IntentDigest string
			ReceiptDigest string
		}
		if e:=tx.Raw("SELECT request_id::text,principal_id::text,run_id,intent_digest,receipt_digest FROM auth_cat49_reviewer_registration WHERE run_id=? OR request_id=? OR principal_id=?",
			input.Receipt.RunID,input.Receipt.RequestID,input.Receipt.PrincipalID).Scan(&old).Error;e!=nil{return e}
		if len(old)>1 {return errors.New("CAT49 conflicting reviewer owner records")}
		if len(old)==1 {
			if old[0].RequestID!=input.Receipt.RequestID || old[0].PrincipalID!=input.Receipt.PrincipalID ||
				old[0].RunID!=input.Receipt.RunID || old[0].IntentDigest!=input.Receipt.IntentDigest ||
				old[0].ReceiptDigest!=input.Receipt.ReceiptDigest {
				return errors.New("CAT49 changed registration replay")
			}
			var user domain.AuthUser
			if e:=tx.Where("id = ? AND email = ?",input.Receipt.PrincipalID,input.Email).First(&user).Error;e!=nil{return e}
			if user.PasswordHash==nil || bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash),[]byte(input.Password))!=nil {
				return errors.New("CAT49 changed credential replay")
			}
			return nil
		}
		var count int64
		if e:=tx.Raw("SELECT count(*) FROM auth_user WHERE id=? OR email=?",input.Receipt.PrincipalID,input.Email).Scan(&count).Error;e!=nil{return e}
		if count!=0 {return errors.New("CAT49 existing Auth principal cannot be adopted")}
		now:=time.Now().UTC()
		hash:=input.PasswordHash
		user:=domain.AuthUser{ID:input.Receipt.PrincipalID,Email:input.Email,EmailVerified:false,PasswordHash:&hash,PasswordUpdatedAt:&now}
		if e:=tx.Create(&user).Error;e!=nil{return e}
		if e:=tx.Exec("INSERT INTO auth_cat49_reviewer_registration(request_id,principal_id,run_id,intent_digest,receipt_digest) VALUES(?,?,?,?,?)",
			input.Receipt.RequestID,input.Receipt.PrincipalID,input.Receipt.RunID,input.Receipt.IntentDigest,input.Receipt.ReceiptDigest).Error;e!=nil{return e}
		created=true
		return nil
	})
	return created,err
}
func (r *authUserRepo) ReadCAT49Registration(ctx context.Context,id string) (domain.CAT49RegistrationReceipt,error) {
	var record struct{
		RequestID string
		PrincipalID string
		RunID string
		IntentDigest string
		ReceiptDigest string
	}
	result:=r.db.WithContext(ctx).Raw("SELECT request_id::text,principal_id::text,run_id,intent_digest,receipt_digest FROM auth_cat49_reviewer_registration WHERE principal_id=?",id).Scan(&record)
	if result.Error!=nil {return domain.CAT49RegistrationReceipt{},result.Error}
	if result.RowsAffected!=1 {return domain.CAT49RegistrationReceipt{},domain.ErrNotFound}
	var database string
	if e:=r.db.WithContext(ctx).Raw("SELECT current_database()").Scan(&database).Error;e!=nil {return domain.CAT49RegistrationReceipt{},e}
	return domain.CAT49RegistrationReceipt{
		Schema:"cat49-disposable-reviewer-registration.v1",RunID:record.RunID,
		RequestID:record.RequestID,PrincipalID:record.PrincipalID,
		AuthDatabase:database,IntentDigest:record.IntentDigest,ReceiptDigest:record.ReceiptDigest,
	},nil
}

// The independent verified RBAC receipt is an append-only activation,
// and email verification is released only by this atomic owner transaction.
func (r *authUserRepo) ActivateCAT49Reviewer(ctx context.Context,input domain.CAT49ReviewerActivation) (bool,error) {
	created:=false
	err:=r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var registration struct{ PrincipalID string; RunID string }
		result:=tx.Raw("SELECT principal_id::text,run_id FROM auth_cat49_reviewer_registration WHERE principal_id=? FOR UPDATE",input.PrincipalID).Scan(&registration)
		if result.Error!=nil{return result.Error}
		if result.RowsAffected!=1{return domain.ErrNotFound}
		if e:=tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?,0))","cat49-auth-reviewer:"+registration.RunID).Error;e!=nil{return e}
		var existing []struct{ RequestID string; RbacReceiptDigest string; ReceiptDigest string }
		if e:=tx.Raw("SELECT request_id::text,rbac_receipt_digest,receipt_digest FROM auth_cat49_reviewer_activation WHERE principal_id=?",input.PrincipalID).Scan(&existing).Error;e!=nil{return e}
		if len(existing)>1 {return errors.New("CAT49 duplicate activation")}
		if len(existing)==1 {
			if existing[0].RequestID!=input.RequestID || existing[0].RbacReceiptDigest!=input.GrantReceiptDigest ||
				existing[0].ReceiptDigest!=input.ActivationReceiptDigest {
				return errors.New("CAT49 conflicting activation replay")
			}
			return nil
		}
		var user domain.AuthUser
		if e:=tx.Clauses(clause.Locking{Strength:"UPDATE"}).Where("id = ?",input.PrincipalID).First(&user).Error;e!=nil{return e}
		if user.EmailVerified {return errors.New("CAT49 principal activated without receipt")}
		if e:=tx.Exec("INSERT INTO auth_cat49_reviewer_activation(principal_id,request_id,rbac_receipt_digest,receipt_digest) VALUES(?,?,?,?)",
			input.PrincipalID,input.RequestID,input.GrantReceiptDigest,input.ActivationReceiptDigest).Error;e!=nil{return e}
		activatedUser := tx.Model(&domain.AuthUser{}).Where("id = ? AND email_verified = false", input.PrincipalID).
			Update("email_verified", true)
		if activatedUser.Error != nil || activatedUser.RowsAffected != 1 {
			return errors.New("CAT49 Auth activation did not change exactly one pending principal")
		}
		created=true
		return nil
	})
	return created,err
}
