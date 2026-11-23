package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/example/auth-service/internal/domain"
)

var ErrMentorIdentityForbidden = errors.New("mentor identity forbidden")

const MentorHTTPOperationTimeout = 3 * time.Second

type MentorHTTPAuthority struct {
	sessions *MentorLiveSessionVerifier
	admins   domain.CanonicalAdminVerifier
	issuer   *MentorRoleDecisionIssuer
}

func NewMentorHTTPAuthority(privatePEM, publicPEM string, sessions *MentorLiveSessionVerifier, admins domain.CanonicalAdminVerifier, intents domain.MentorCommittedIntentVerifier) (*MentorHTTPAuthority, error) {
	if !sessions.configured() || mentorAuthorityMissing(admins) || mentorAuthorityMissing(intents) {
		return nil, ErrMentorSessionUnavailable
	}
	issuer, err := NewMentorRoleDecisionIssuer(privatePEM, publicPEM, sessions, admins, intents)
	if err != nil {
		return nil, err
	}
	return &MentorHTTPAuthority{sessions: sessions, admins: admins, issuer: issuer}, nil
}

// Configured checks construction only. It is not a session or authorization
// result, and callers must still execute the relevant operation for every call.
func (a *MentorHTTPAuthority) Configured() bool {
	return a != nil && a.sessions.configured() && !mentorAuthorityMissing(a.admins) &&
		a.issuer != nil && a.issuer.sessions == a.sessions && a.issuer.key != nil &&
		a.issuer.clock != nil && !mentorAuthorityMissing(a.issuer.admins) && !mentorAuthorityMissing(a.issuer.intents)
}

func (a *MentorHTTPAuthority) VerifyUser(ctx context.Context, bearer string) (string, error) {
	if !a.Configured() || ctx == nil || ctx.Err() != nil {
		return "", ErrMentorSessionUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, MentorHTTPOperationTimeout)
	defer cancel()
	verified, err := a.sessions.VerifyToken(ctx, "", bearer)
	if err != nil {
		return "", err
	}
	if ctx.Err() != nil || verified == nil {
		return "", ErrMentorSessionUnavailable
	}
	return verified.UserID, nil
}

func (a *MentorHTTPAuthority) VerifyAdmin(ctx context.Context, bearer string) (string, error) {
	if !a.Configured() || ctx == nil || ctx.Err() != nil {
		return "", ErrMentorSessionUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, MentorHTTPOperationTimeout)
	defer cancel()
	verified, err := a.sessions.VerifyToken(ctx, "", bearer)
	if err != nil {
		return "", err
	}
	if verified == nil || ctx.Err() != nil {
		return "", ErrMentorSessionUnavailable
	}
	actor := verified.UserID
	sid, ok := verified.Claims["sid"].(string)
	if !ok || !canonicalMentorUUID(sid) {
		return "", ErrMentorSessionUnavailable
	}
	admin, err := a.admins.ConfirmCanonicalAdmin(ctx, actor)
	if ctx.Err() != nil || err != nil {
		return "", ErrMentorSessionUnavailable
	}
	if admin == nil || admin.ActorID != actor || !admin.UniqueCanonicalDefaultAdmin {
		return "", ErrMentorIdentityForbidden
	}
	current, err := a.sessions.VerifyToken(ctx, "", bearer)
	if err != nil {
		return "", err
	}
	if ctx.Err() != nil || current == nil {
		return "", ErrMentorSessionUnavailable
	}
	currentSID, ok := current.Claims["sid"].(string)
	if !ok || current.UserID != actor || currentSID != sid {
		return "", ErrMentorSessionUnauthenticated
	}
	return actor, nil
}

func (a *MentorHTTPAuthority) Issue(ctx context.Context, bearer string, request domain.MentorRoleDecisionRequest) (string, error) {
	if !a.Configured() || ctx == nil || ctx.Err() != nil {
		return "", ErrMentorSessionUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, MentorHTTPOperationTimeout)
	defer cancel()
	proof, err := a.issuer.Issue(ctx, "", bearer, request)
	if ctx.Err() != nil {
		return "", ErrMentorSessionUnavailable
	}
	return proof, err
}
