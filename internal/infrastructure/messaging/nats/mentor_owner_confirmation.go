package natsadapter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	nats "github.com/nats-io/nats.go"
)

const (
	MentorCanonicalAdminLookupSubject  = "rbac.checkMentorCanonicalAdmin.v1"
	MentorCommittedIntentLookupSubject = "mentor.confirmCommittedRoleIntent.v1"
	mentorLookupTokenLimit             = 8192
	mentorLookupEnvelopeLimit          = 16384
	mentorLookupMaxInteger             = int64(9007199254740991)
	mentorLookupTTL                    = int64(30)
	mentorOwnerReplyTTL                = int64(15)
)

var ErrMentorOwnerConfirmationUnavailable = errors.New("mentor owner confirmation unavailable")

type MentorOwnerNATSRequester interface {
	RequestWithContext(context.Context, string, []byte) (*nats.Msg, error)
}

// MentorOwnerConfirmationClient is a source-only outbound adapter for the two
// authenticated owner ports. It never forwards a user token, caches authority,
// retries automatically, or grants a role. Construction does not mount it.
type MentorOwnerConfirmationClient struct {
	requester MentorOwnerNATSRequester
	lookupKey *rsa.PrivateKey
	rbacKey   *rsa.PublicKey
	mentorKey *rsa.PublicKey
	now       func() time.Time
}

func NewMentorOwnerConfirmationClient(requester MentorOwnerNATSRequester, authLookupPrivatePEM, authLookupPublicPEM, rbacReplyPublicPEM, mentorReplyPublicPEM string) (*MentorOwnerConfirmationClient, error) {
	if missingMentorRequester(requester) {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	private, err := parseMentorLookupPrivateKey(authLookupPrivatePEM)
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	public, err := parseReviewerPermissionDecisionPublicKey(authLookupPublicPEM)
	if err != nil || !sameMentorLookupKey(public, &private.PublicKey) {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	rbac, err := parseReviewerPermissionDecisionPublicKey(rbacReplyPublicPEM)
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	mentor, err := parseReviewerPermissionDecisionPublicKey(mentorReplyPublicPEM)
	if err != nil || sameMentorLookupKey(rbac, mentor) || sameMentorLookupKey(public, rbac) || sameMentorLookupKey(public, mentor) {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	return &MentorOwnerConfirmationClient{requester: requester, lookupKey: private, rbacKey: rbac, mentorKey: mentor, now: time.Now}, nil
}

func (c *MentorOwnerConfirmationClient) ConfirmCanonicalAdmin(ctx context.Context, actor string) (*domain.CanonicalAdminConfirmation, error) {
	if !validNonZeroCanonicalReviewerUUID(actor) {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	reply, err := c.lookup(ctx, actor, nil)
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	return &domain.CanonicalAdminConfirmation{ActorID: actor, UniqueCanonicalDefaultAdmin: reply.Decision == "ALLOW"}, nil
}

func (c *MentorOwnerConfirmationClient) ConfirmCommittedMentorIntent(ctx context.Context, binding domain.MentorRoleDecisionBinding) (*domain.MentorCommittedIntentConfirmation, error) {
	if !validMentorLookupBinding(binding) {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	reply, err := c.lookup(ctx, binding.AdminActorID, &binding)
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	allowed := reply.Result == "ALLOW"
	return &domain.MentorCommittedIntentConfirmation{Binding: binding, Committed: allowed, Current: allowed, State: reply.State}, nil
}

type mentorOwnerOperation struct {
	subject, audience, typ, purpose                     string
	replyIssuer, replyAudience, replyType, replyPurpose string
}

func mentorLookupOperation(intent bool) mentorOwnerOperation {
	if intent {
		return mentorOwnerOperation{
			subject: MentorCommittedIntentLookupSubject, audience: "ms-go-mentor-committed-role-intent", typ: "mentor_committed_role_intent_check", purpose: "AUTH_MENTOR_COMMITTED_ROLE_INTENT_V1",
			replyIssuer: "ms-go-mentor", replyAudience: "ms-go-auth-mentor-committed-role-intent-decision", replyType: "mentor_committed_role_intent_decision", replyPurpose: "MENTOR_AUTH_COMMITTED_ROLE_INTENT_DECISION_V1",
		}
	}
	return mentorOwnerOperation{
		subject: MentorCanonicalAdminLookupSubject, audience: "ms-go-rbac-mentor-canonical-admin", typ: "mentor_canonical_admin_check", purpose: "AUTH_RBAC_MENTOR_CANONICAL_ADMIN_LOOKUP_V1",
		replyIssuer: "ms-go-rbac", replyAudience: "ms-go-auth-mentor-canonical-admin-decision", replyType: "mentor_canonical_admin_decision", replyPurpose: "RBAC_AUTH_MENTOR_CANONICAL_ADMIN_DECISION_V1",
	}
}

type mentorOwnerReplyClaims struct {
	Issuer              string `json:"iss"`
	Audience            string `json:"aud"`
	Actor               string `json:"sub"`
	Type                string `json:"typ"`
	Purpose             string `json:"purpose"`
	Subject             string `json:"subject"`
	JWTID               string `json:"jti"`
	IssuedAt            int64  `json:"iat"`
	ExpiresAt           int64  `json:"exp"`
	Decision            string `json:"decision"`
	RequestJWTID        string `json:"request_jti"`
	RequestDigest       string `json:"request_digest"`
	TargetUserID        string `json:"target_user_id"`
	ApplicationID       string `json:"application_id"`
	ApplicationRevision int64  `json:"application_revision"`
	CommandID           string `json:"request_id"`
	DecisionDigest      string `json:"decision_digest"`
	Result              string `json:"result"`
	State               string `json:"state"`
}

func (c *MentorOwnerConfirmationClient) lookup(ctx context.Context, actor string, binding *domain.MentorRoleDecisionBinding) (*mentorOwnerReplyClaims, error) {
	if c == nil || c.lookupKey == nil || c.rbacKey == nil || c.mentorKey == nil || c.now == nil || missingMentorRequester(c.requester) || ctx == nil || ctx.Err() != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	op := mentorLookupOperation(binding != nil)
	issuedAt := c.now().Unix()
	if issuedAt <= 0 || issuedAt > mentorLookupMaxInteger-mentorLookupTTL {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	expiresAt := issuedAt + mentorLookupTTL
	jti, err := newMentorLookupJTI()
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	claims := map[string]any{
		"iss": "ms-go-auth", "aud": op.audience, "sub": actor, "typ": op.typ, "purpose": op.purpose,
		"subject": op.subject, "jti": jti, "iat": issuedAt, "exp": expiresAt,
	}
	if binding != nil {
		claims["target_user_id"], claims["application_id"], claims["application_revision"] = binding.TargetUserID, binding.ApplicationID, binding.ApplicationRevision
		claims["decision"], claims["request_id"], claims["decision_digest"] = binding.Decision, binding.RequestID, binding.DecisionDigest
	}
	proof, err := c.signLookup(claims)
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	body, err := json.Marshal(struct {
		Proof string `json:"proof"`
	}{Proof: proof})
	if err != nil || len(body) > mentorLookupEnvelopeLimit || ctx.Err() != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	message, err := c.requester.RequestWithContext(ctx, op.subject, body)
	if ctx.Err() != nil || err != nil || message == nil || len(message.Data) == 0 || len(message.Data) > mentorLookupEnvelopeLimit {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	var envelope struct {
		DecisionJWT string `json:"decision_jwt"`
	}
	if strictReviewerDecisionJSON(message.Data, []string{"decision_jwt"}, &envelope) != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	public := c.rbacKey
	if binding != nil {
		public = c.mentorKey
	}
	reply, err := verifyMentorOwnerReply(envelope.DecisionJWT, public, binding != nil)
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	digest := sha256.Sum256([]byte(proof))
	if reply.Issuer != op.replyIssuer || reply.Audience != op.replyAudience || reply.Type != op.replyType || reply.Purpose != op.replyPurpose ||
		reply.Actor != actor || reply.Subject != op.subject || reply.RequestJWTID != jti || reply.RequestDigest != hex.EncodeToString(digest[:]) ||
		!validNonZeroCanonicalReviewerUUID(reply.JWTID) || reply.JWTID == jti {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	if binding == nil {
		if reply.Decision != "ALLOW" && reply.Decision != "DENY" {
			return nil, ErrMentorOwnerConfirmationUnavailable
		}
	} else {
		if reply.TargetUserID != binding.TargetUserID || reply.ApplicationID != binding.ApplicationID || reply.ApplicationRevision != binding.ApplicationRevision ||
			reply.Decision != binding.Decision || reply.CommandID != binding.RequestID || reply.DecisionDigest != binding.DecisionDigest {
			return nil, ErrMentorOwnerConfirmationUnavailable
		}
		wantState := domain.MentorApprovalPendingGrant
		if binding.Decision == "SUSPEND" {
			wantState = domain.MentorSuspended
		}
		if reply.Result == "DENY" {
			wantState = "UNCONFIRMED"
		} else if reply.Result != "ALLOW" {
			return nil, ErrMentorOwnerConfirmationUnavailable
		}
		if reply.State != wantState {
			return nil, ErrMentorOwnerConfirmationUnavailable
		}
	}
	now := c.now().Unix()
	if !validMentorLookupTime(issuedAt, expiresAt, now, mentorLookupTTL) || !validMentorLookupTime(reply.IssuedAt, reply.ExpiresAt, now, mentorOwnerReplyTTL) ||
		reply.ExpiresAt > expiresAt || ctx.Err() != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	return reply, nil
}

func (c *MentorOwnerConfirmationClient) signLookup(claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", ErrMentorOwnerConfirmationUnavailable
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.lookupKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", ErrMentorOwnerConfirmationUnavailable
	}
	proof := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(proof) > mentorLookupTokenLimit {
		return "", ErrMentorOwnerConfirmationUnavailable
	}
	return proof, nil
}

func verifyMentorOwnerReply(token string, public *rsa.PublicKey, intent bool) (*mentorOwnerReplyClaims, error) {
	if token == "" || len(token) > mentorLookupTokenLimit {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	headerBytes, err := decodeCanonicalJWTPart(parts[0])
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	var header reviewerPermissionDecisionJWTHeader
	if strictReviewerDecisionJSON(headerBytes, []string{"alg", "typ"}, &header) != nil || header.Algorithm != "RS256" || header.Type != "JWT" {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	payload, err := decodeCanonicalJWTPart(parts[1])
	if err != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	signature, err := decodeCanonicalJWTPart(parts[2])
	if err != nil || len(signature) != public.Size() {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	fields := []string{"iss", "aud", "sub", "typ", "purpose", "subject", "jti", "iat", "exp", "decision", "request_jti", "request_digest"}
	if intent {
		fields = append(fields, "target_user_id", "application_id", "application_revision", "request_id", "decision_digest", "result", "state")
	}
	var claims mentorOwnerReplyClaims
	if strictReviewerDecisionJSON(payload, fields, &claims) != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	return &claims, nil
}

func validMentorLookupTime(issuedAt, expiresAt, now, ttl int64) bool {
	return now > 0 && now <= mentorLookupMaxInteger && issuedAt > 0 && issuedAt <= mentorLookupMaxInteger &&
		expiresAt > now && expiresAt <= mentorLookupMaxInteger && expiresAt > issuedAt && expiresAt-issuedAt <= ttl &&
		(issuedAt <= now || issuedAt-now <= 5)
}

func validMentorLookupBinding(binding domain.MentorRoleDecisionBinding) bool {
	validDecision := binding.Decision == "APPROVE" && binding.ApplicationRevision == 2 ||
		binding.Decision == "SUSPEND" && (binding.ApplicationRevision == 3 || binding.ApplicationRevision == 4)
	if !validNonZeroCanonicalReviewerUUID(binding.AdminActorID) || !validNonZeroCanonicalReviewerUUID(binding.TargetUserID) ||
		!validNonZeroCanonicalReviewerUUID(binding.ApplicationID) || !validNonZeroCanonicalReviewerUUID(binding.RequestID) ||
		!validDecision {
		return false
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{binding.Decision, binding.AdminActorID, binding.ApplicationID, binding.RequestID, strconv.FormatInt(binding.ApplicationRevision-1, 10)}, "|")))
	return binding.DecisionDigest == hex.EncodeToString(digest[:])
}

func newMentorLookupJTI() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", ErrMentorOwnerConfirmationUnavailable
	}
	uuid[6], uuid[8] = uuid[6]&0x0f|0x40, uuid[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

func parseMentorLookupPrivateKey(encoded string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	var parsed any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 || key.Validate() != nil {
		return nil, ErrMentorOwnerConfirmationUnavailable
	}
	key.Precompute()
	return key, nil
}

func sameMentorLookupKey(first, second *rsa.PublicKey) bool {
	return first != nil && second != nil && first.E == second.E && first.N.Cmp(second.N) == 0
}

func missingMentorRequester(requester MentorOwnerNATSRequester) bool {
	if requester == nil {
		return true
	}
	value := reflect.ValueOf(requester)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}

var (
	_ domain.CanonicalAdminVerifier        = (*MentorOwnerConfirmationClient)(nil)
	_ domain.MentorCommittedIntentVerifier = (*MentorOwnerConfirmationClient)(nil)
)
