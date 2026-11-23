package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/tokenverify"
)

var (
	ErrMentorSessionUnauthenticated = errors.New("mentor session unauthenticated")
	ErrMentorSessionUnavailable     = domain.ErrMentorSessionUnavailable
)

type MentorLiveSessionVerifier struct {
	parser tokenverify.Parser
	reader domain.MentorSessionReader
	clock  func() time.Time
}

func NewMentorLiveSessionVerifier(parser tokenverify.Parser, reader domain.MentorSessionReader) (*MentorLiveSessionVerifier, error) {
	if mentorAuthorityMissing(parser) || mentorAuthorityMissing(reader) {
		return nil, ErrMentorSessionUnavailable
	}
	return &MentorLiveSessionVerifier{parser: parser, reader: reader, clock: time.Now}, nil
}

// VerifyToken requires both current cryptographic access-token validity and the
// exact active Auth-owned persisted session. It never falls back to JWT-only
// authorization, returns unnecessary claims, logs a trace supplied by a caller,
// or retains the presented credential.
func (v *MentorLiveSessionVerifier) VerifyToken(ctx context.Context, _ string, bearer string) (*VerificationResult, error) {
	if !v.configured() || ctx == nil || ctx.Err() != nil {
		return nil, ErrMentorSessionUnavailable
	}
	if !domain.ValidMentorAccessToken(bearer) {
		return nil, ErrMentorSessionUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, MentorHTTPOperationTimeout)
	defer cancel()
	started := v.clock()
	if !validMentorSessionClock(started) {
		return nil, ErrMentorSessionUnavailable
	}
	verified, err := tokenverify.Verify(v.parser, bearer, func() time.Time { return started })
	if ctx.Err() != nil {
		return nil, ErrMentorSessionUnavailable
	}
	if err != nil || verified == nil || !canonicalMentorUUID(verified.UserID) {
		return nil, ErrMentorSessionUnauthenticated
	}
	sid, ok := verified.Claims["sid"].(string)
	_, hasType := verified.Claims["typ"]
	expiry, validExpiry := mentorSessionExpiry(verified.Claims["exp"])
	if !ok || !canonicalMentorUUID(sid) || hasType || !validExpiry || expiry <= started.Unix() {
		return nil, ErrMentorSessionUnauthenticated
	}
	actor := verified.UserID
	hash := hashToken(sid)
	session, err := v.reader.FindActive(ctx, hash)
	if ctx.Err() != nil {
		return nil, ErrMentorSessionUnavailable
	}
	if err == domain.ErrNotFound {
		return nil, ErrMentorSessionUnauthenticated
	}
	if err != nil || session == nil || session.UserID != actor || session.RefreshTokenHash != hash ||
		session.ExpiresAt.IsZero() || !validMentorSessionClock(session.ExpiresAt) {
		return nil, ErrMentorSessionUnavailable
	}
	finished := v.clock()
	if !validMentorSessionClock(finished) || finished.Before(started) {
		return nil, ErrMentorSessionUnavailable
	}
	if session.RevokedAt != nil || !session.ExpiresAt.After(finished) || expiry <= finished.Unix() {
		return nil, ErrMentorSessionUnauthenticated
	}
	if ctx.Err() != nil {
		return nil, ErrMentorSessionUnavailable
	}
	return &VerificationResult{UserID: actor, Claims: map[string]any{"sid": sid, "exp": expiry}}, nil
}

func (v *MentorLiveSessionVerifier) configured() bool {
	return v != nil && !mentorAuthorityMissing(v.parser) && !mentorAuthorityMissing(v.reader) && v.clock != nil
}

func validMentorSessionClock(now time.Time) bool {
	return now.Unix() > 0 && now.Unix() <= domain.MentorRoleDecisionMaxInteger
}

func mentorSessionExpiry(value any) (int64, bool) {
	var expiry int64
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) || v <= 0 || v > float64(domain.MentorRoleDecisionMaxInteger) {
			return 0, false
		}
		expiry = int64(v)
	case json.Number:
		var err error
		expiry, err = strconv.ParseInt(string(v), 10, 64)
		if err != nil || strconv.FormatInt(expiry, 10) != string(v) {
			return 0, false
		}
	case int64:
		expiry = v
	case int:
		expiry = int64(v)
	default:
		return 0, false
	}
	return expiry, expiry > 0 && expiry <= domain.MentorRoleDecisionMaxInteger
}
