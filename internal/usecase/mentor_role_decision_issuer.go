package usecase

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMentorRoleDecisionDenied      = errors.New("mentor role decision denied")
	ErrMentorRoleDecisionUnavailable = errors.New("mentor role decision authority unavailable")
	ErrMentorRoleDecisionInvalid     = errors.New("invalid mentor role decision")
)

// MentorSessionVerifier is the existing Auth-owned live-session verification
// boundary. The production authService implements it; it is not a JWT-only port.
type MentorSessionVerifier interface {
	VerifyToken(context.Context, string, string) (*VerificationResult, error)
}

// MentorRoleDecisionIssuer is additive and deliberately unmounted. Its ports
// must be authenticated owner adapters; test fixtures are not runtime authority.
// It retains neither bearer tokens nor previous session/authorization results.
type MentorRoleDecisionIssuer struct {
	key      *rsa.PrivateKey
	sessions MentorSessionVerifier
	admins   domain.CanonicalAdminVerifier
	intents  domain.MentorCommittedIntentVerifier
	clock    func() time.Time
}

// NewMentorRoleDecisionIssuer requires a dedicated Mentor key pair. It does not
// read access-token keys, choose a shared-secret fallback, or supply any adapter.
func NewMentorRoleDecisionIssuer(privateKeyPEM, publicKeyPEM string, sessions MentorSessionVerifier, admins domain.CanonicalAdminVerifier, intents domain.MentorCommittedIntentVerifier) (*MentorRoleDecisionIssuer, error) {
	if mentorAuthorityMissing(sessions) || mentorAuthorityMissing(admins) || mentorAuthorityMissing(intents) ||
		strings.TrimSpace(privateKeyPEM) == "" || strings.TrimSpace(publicKeyPEM) == "" {
		return nil, ErrMentorRoleDecisionUnavailable
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, ErrMentorRoleDecisionUnavailable
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPEM))
	if err != nil || publicKey == nil || publicKey.N == nil || publicKey.N.Cmp(key.N) != 0 || publicKey.E != key.E {
		return nil, ErrMentorRoleDecisionUnavailable
	}
	return &MentorRoleDecisionIssuer{key: key, sessions: sessions, admins: admins, intents: intents, clock: time.Now}, nil
}

func (issuer *MentorRoleDecisionIssuer) Issue(ctx context.Context, traceID, accessToken string, request domain.MentorRoleDecisionRequest) (string, error) {
	if issuer == nil || issuer.key == nil || issuer.clock == nil || ctx == nil ||
		mentorAuthorityMissing(issuer.sessions) || mentorAuthorityMissing(issuer.admins) || mentorAuthorityMissing(issuer.intents) {
		return "", ErrMentorRoleDecisionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validMentorRoleRequest(request) {
		return "", ErrMentorRoleDecisionInvalid
	}
	if strings.TrimSpace(accessToken) == "" {
		return "", ErrMentorRoleDecisionDenied
	}
	verified, err := issuer.sessions.VerifyToken(ctx, traceID, accessToken)
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	if err != nil {
		return "", mentorRoleSessionFailure(err)
	}
	if verified == nil || !canonicalMentorUUID(verified.UserID) {
		return "", ErrMentorRoleDecisionDenied
	}
	// Existing current Auth access tokens have a persisted sid and no typ claim.
	// A legacy stateless token, refresh token or another purpose's proof cannot
	// become Mentor authority even if a JWT-only implementation accepted it.
	sid, ok := verified.Claims["sid"].(string)
	_, hasProofType := verified.Claims["typ"]
	if !ok || !canonicalMentorUUID(sid) || hasProofType {
		return "", ErrMentorRoleDecisionDenied
	}
	actor := verified.UserID
	digest := sha256.Sum256([]byte(strings.Join([]string{
		request.Decision, actor, request.ApplicationID, request.RequestID,
		strconv.FormatInt(request.ApplicationRevision-1, 10),
	}, "|")))
	if request.DecisionDigest != hex.EncodeToString(digest[:]) {
		return "", ErrMentorRoleDecisionInvalid
	}
	admin, err := issuer.admins.ConfirmCanonicalAdmin(ctx, actor)
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	if err != nil {
		return "", ErrMentorRoleDecisionUnavailable
	}
	if admin == nil || admin.ActorID != actor || !admin.UniqueCanonicalDefaultAdmin {
		return "", ErrMentorRoleDecisionDenied
	}
	binding := domain.MentorRoleDecisionBinding{MentorRoleDecisionRequest: request, AdminActorID: actor}
	intent, err := issuer.intents.ConfirmCommittedMentorIntent(ctx, binding)
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	if err != nil {
		return "", ErrMentorRoleDecisionUnavailable
	}
	wantState := domain.MentorApprovalPendingGrant
	if request.Decision == "SUSPEND" {
		wantState = domain.MentorSuspended
	}
	if intent == nil || !intent.Committed || !intent.Current || intent.State != wantState || intent.Binding != binding {
		return "", ErrMentorRoleDecisionDenied
	}
	// Owner confirmations can be delayed. Recheck the same presented credential
	// and immutable actor/session binding before signing; a stored actor ID or
	// a different session must never renew this command's authority.
	current, err := issuer.sessions.VerifyToken(ctx, traceID, accessToken)
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	if err != nil {
		return "", mentorRoleSessionFailure(err)
	}
	if current == nil || current.UserID != actor {
		return "", ErrMentorRoleDecisionDenied
	}
	currentSID, hasSID := current.Claims["sid"].(string)
	_, currentHasType := current.Claims["typ"]
	if !hasSID || currentSID != sid || currentHasType {
		return "", ErrMentorRoleDecisionDenied
	}
	jti, err := GenerateJTI()
	if err != nil {
		return "", ErrMentorRoleDecisionUnavailable
	}
	now := issuer.clock().Unix()
	// Bound before addition, so both overflow and precision-loss timestamps deny.
	if now <= 0 || now > domain.MentorRoleDecisionMaxInteger-domain.MentorRoleDecisionTTLSeconds {
		return "", ErrMentorRoleDecisionUnavailable
	}
	claims := jwt.MapClaims{
		"iss": domain.MentorRoleDecisionIssuer, "aud": domain.MentorRoleDecisionAudience,
		"sub": actor, "typ": domain.MentorRoleDecisionType, "purpose": domain.MentorRoleDecisionPurpose,
		"target_user_id": request.TargetUserID, "application_id": request.ApplicationID,
		"application_revision": request.ApplicationRevision, "decision": request.Decision,
		"request_id": request.RequestID, "decision_digest": request.DecisionDigest,
		"role": domain.MentorRoleDecisionRole, "service": domain.MentorRoleDecisionService,
		"jti": jti, "iat": now, "exp": now + domain.MentorRoleDecisionTTLSeconds,
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(issuer.key)
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	if err != nil || len(signed) > domain.MentorRoleDecisionMaxBytes {
		return "", ErrMentorRoleDecisionUnavailable
	}
	finished := issuer.clock().Unix()
	if finished < now || finished >= now+domain.MentorRoleDecisionTTLSeconds {
		return "", ErrMentorRoleDecisionUnavailable
	}
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	return signed, nil
}

func mentorRoleSessionFailure(err error) error {
	// The strict production boundary returns these exact credential-neutral
	// sentinels. Do not inspect diagnostics or classify mixed/unknown legacy
	// error trees as a known outage or known unauthenticated result.
	switch err {
	case ErrMentorSessionUnavailable:
		return ErrMentorRoleDecisionUnavailable
	case ErrMentorSessionUnauthenticated:
		return ErrMentorSessionUnauthenticated
	default:
		return ErrMentorRoleDecisionDenied
	}
}

func validMentorRoleRequest(request domain.MentorRoleDecisionRequest) bool {
	if !canonicalMentorUUID(request.TargetUserID) || !canonicalMentorUUID(request.ApplicationID) || !canonicalMentorUUID(request.RequestID) ||
		len(request.DecisionDigest) != sha256.Size*2 || request.DecisionDigest != strings.ToLower(request.DecisionDigest) {
		return false
	}
	if _, err := hex.DecodeString(request.DecisionDigest); err != nil {
		return false
	}
	return request.Decision == "APPROVE" && request.ApplicationRevision == 2 ||
		request.Decision == "SUSPEND" && (request.ApplicationRevision == 3 || request.ApplicationRevision == 4)
}

func canonicalMentorUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}

func mentorAuthorityMissing(port any) bool {
	if port == nil {
		return true
	}
	v := reflect.ValueOf(port)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
