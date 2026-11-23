package usecase

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/example/auth-service/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

var ErrCAT49ReviewerDenied = errors.New("CAT49 reviewer operator denied")
var cat49ReviewerID = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
var cat49ReviewerRun = regexp.MustCompile("^cat49[a-z0-9]{5,20}$")
var cat49ReviewerDB = regexp.MustCompile("^cat49_[a-z0-9_]{4,60}$")
var cat49ReviewerDigest = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
var cat49ReviewerOperator = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

type CAT49RegistrationCommand struct {
	RunID, RequestID, PrincipalID, AuthDatabase, Operator, Password string
}

func cat49OwnerDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func cat49OwnerMAC(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	return "sha256:" + hex.EncodeToString(m.Sum(nil))
}
func cat49OwnerSame(a, b string) bool {
	return cat49ReviewerDigest.MatchString(a) && cat49ReviewerDigest.MatchString(b) && hmac.Equal([]byte(a), []byte(b))
}
func cat49RegBase(p domain.CAT49RegistrationReceipt) map[string]string {
	return map[string]string{"schema": p.Schema, "run_id": p.RunID, "request_id": p.RequestID,
		"principal_id": p.PrincipalID, "auth_database": p.AuthDatabase, "intent_digest": p.IntentDigest}
}
func cat49RegSigned(p domain.CAT49RegistrationReceipt) map[string]string {
	base := cat49RegBase(p)
	base["receipt_digest"] = p.ReceiptDigest
	return base
}
func CAT49RegisterReviewer(ctx context.Context, store domain.CAT49ReviewerOperatorStore,
	in CAT49RegistrationCommand, key []byte) (domain.CAT49RegistrationReceipt, error) {
	var empty domain.CAT49RegistrationReceipt
	if store == nil || len(key) < 32 || len(key) > 4096 ||
		!cat49ReviewerRun.MatchString(in.RunID) || !cat49ReviewerID.MatchString(in.RequestID) ||
		!cat49ReviewerID.MatchString(in.PrincipalID) || !cat49ReviewerDB.MatchString(in.AuthDatabase) ||
		!cat49ReviewerOperator.MatchString(in.Operator) || len(in.Password) < 8 || len(in.Password) > 72 ||
		strings.ContainsAny(in.Password, "\x00\r\n") {
		return empty, ErrCAT49ReviewerDenied
	}
	email := "cat49+" + in.RunID + "-" + in.PrincipalID[:8] + "@verification.invalid"
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return empty, ErrCAT49ReviewerDenied
	}
	intent, _ := json.Marshal(map[string]string{"schema": "cat49-disposable-reviewer-intent.v1",
		"run_id": in.RunID, "request_id": in.RequestID, "principal_id": in.PrincipalID,
		"email": email, "auth_database": in.AuthDatabase, "operator": in.Operator})
	proof := domain.CAT49RegistrationReceipt{Schema: "cat49-disposable-reviewer-registration.v1",
		RunID: in.RunID, RequestID: in.RequestID, PrincipalID: in.PrincipalID,
		AuthDatabase: in.AuthDatabase, IntentDigest: cat49OwnerDigest(intent)}
	body, _ := json.Marshal(cat49RegBase(proof))
	proof.ReceiptDigest = cat49OwnerDigest(body)
	signed, _ := json.Marshal(cat49RegSigned(proof))
	proof.Signature = cat49OwnerMAC(key, signed)
	_, err = store.RegisterCAT49Reviewer(ctx, domain.CAT49ReviewerRegistration{
		Receipt: proof, Email: email, Password: in.Password, PasswordHash: string(hash)})
	if err != nil {
		return empty, ErrCAT49ReviewerDenied
	}
	return proof, nil
}
func cat49GrantBase(p domain.CAT49GrantReceipt) map[string]string {
	return map[string]string{
		"schema": p.Schema, "run_id": p.RunID, "request_id": p.RequestID,
		"principal_id": p.PrincipalID, "auth_receipt_digest": p.AuthReceiptDigest,
		"role": p.Role, "operator": p.Operator, "applied_at": p.AppliedAt,
	}
}
func cat49VerifyGrant(raw, key []byte) (domain.CAT49GrantReceipt, error) {
	var p domain.CAT49GrantReceipt
	if len(key) < 32 || len(key) > 4096 || len(raw) > 4096 {
		return p, ErrCAT49ReviewerDenied
	}
	payload := bytes.TrimSpace(raw)
	if json.Unmarshal(payload, &p) != nil {
		return p, ErrCAT49ReviewerDenied
	}
	canonical, _ := json.Marshal(p)
	if !bytes.Equal(payload, canonical) || p.Schema != "cat49-disposable-reviewer-grant.v1" ||
		p.Role != "moderator" || !cat49ReviewerRun.MatchString(p.RunID) ||
		!cat49ReviewerID.MatchString(p.PrincipalID) || !cat49ReviewerID.MatchString(p.RequestID) ||
		!cat49ReviewerDigest.MatchString(p.AuthReceiptDigest) || p.AppliedAt == "" {
		return p, ErrCAT49ReviewerDenied
	}
	body, _ := json.Marshal(cat49GrantBase(p))
	if !cat49OwnerSame(p.ReceiptDigest, cat49OwnerDigest(body)) {
		return p, ErrCAT49ReviewerDenied
	}
	signedFields := cat49GrantBase(p)
	signedFields["receipt_digest"] = p.ReceiptDigest
	signed, _ := json.Marshal(signedFields)
	if !cat49OwnerSame(p.Signature, cat49OwnerMAC(key, signed)) {
		return p, ErrCAT49ReviewerDenied
	}
	return p, nil
}
func CAT49ActivateReviewer(ctx context.Context, store domain.CAT49ReviewerOperatorStore,
	roles domain.RoleClient, principalID string, rbacProof, rbacKey []byte) error {
	if store == nil || roles == nil || !cat49ReviewerID.MatchString(principalID) {
		return ErrCAT49ReviewerDenied
	}
	grant, err := cat49VerifyGrant(rbacProof, rbacKey)
	if err != nil || grant.PrincipalID != principalID {
		return ErrCAT49ReviewerDenied
	}
	registered, err := store.ReadCAT49Registration(ctx, principalID)
	if err != nil || registered.PrincipalID != principalID || registered.RunID != grant.RunID ||
		registered.ReceiptDigest != grant.AuthReceiptDigest {
		return ErrCAT49ReviewerDenied
	}
	allowed, err := roles.CheckRole(ctx, principalID, "moderator")
	if err != nil || !allowed {
		return ErrCAT49ReviewerDenied
	}
	for _, unwanted := range []string{"admin", "student"} {
		current, e := roles.CheckRole(ctx, principalID, unwanted)
		if e != nil || current {
			return ErrCAT49ReviewerDenied
		}
	}
	activation := domain.CAT49ReviewerActivation{PrincipalID: principalID, RequestID: grant.RequestID,
		GrantReceiptDigest: grant.ReceiptDigest}
	receipt, _ := json.Marshal(map[string]string{"schema": "cat49-disposable-reviewer-activation.v1",
		"principal_id": principalID, "request_id": grant.RequestID,
		"grant_receipt_digest": grant.ReceiptDigest, "registration_digest": registered.ReceiptDigest})
	activation.ActivationReceiptDigest = cat49OwnerDigest(receipt)
	_, err = store.ActivateCAT49Reviewer(ctx, activation)
	if err != nil {
		return ErrCAT49ReviewerDenied
	}
	return nil
}
