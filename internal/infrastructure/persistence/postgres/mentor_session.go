package repo

import (
	"context"
	"encoding/hex"
	"reflect"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type mentorSessionReader struct{ source domain.MentorSessionReader }

func NewMentorSessionReader(db *gorm.DB) (domain.MentorSessionReader, error) {
	if db == nil || db.Config == nil || db.Statement == nil || db.Statement.ConnPool == nil {
		return nil, domain.ErrMentorSessionUnavailable
	}
	// The existing lookup can otherwise interpolate rt:<sid> and driver details
	// into GORM trace logs. Silence only this new boundary's cloned DB session;
	// the supplied DB and all legacy callers retain their existing logger.
	privateSession := db.Session(&gorm.Session{Logger: logger.Discard})
	return &mentorSessionReader{source: NewRefreshTokenRepository(privateSession)}, nil
}

func (r *mentorSessionReader) FindActive(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	if r == nil || mentorSessionSourceMissing(r.source) || ctx == nil || ctx.Err() != nil ||
		!mentorSessionLookupKeyValid(hash) {
		return nil, domain.ErrMentorSessionUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	session, err := r.source.FindActive(ctx, hash)
	if ctx.Err() != nil {
		return nil, domain.ErrMentorSessionUnavailable
	}
	if mentorSessionKnownAbsent(err) {
		return nil, domain.ErrNotFound
	}
	if err != nil || session == nil {
		return nil, domain.ErrMentorSessionUnavailable
	}
	copy := *session
	if session.RevokedAt != nil {
		revoked := *session.RevokedAt
		copy.RevokedAt = &revoked
	}
	return &copy, nil
}

func mentorSessionLookupKeyValid(key string) bool {
	// Preserve Auth's current owner representation. The legacy field is named
	// RefreshTokenHash, but hashToken(sid) currently encodes exactly rt:<sid>.
	if len(key) != 39 || !strings.HasPrefix(key, "rt:") {
		return false
	}
	id := key[3:]
	if id != strings.ToLower(id) || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
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

func mentorSessionKnownAbsent(err error) bool {
	// A single known-not-found error may be wrapped. Mixed error trees are not
	// semantic absence and must not hide an accompanying storage failure.
	for depth := 0; depth < 16 && err != nil; depth++ {
		if err == gorm.ErrRecordNotFound || err == domain.ErrNotFound {
			return true
		}
		wrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}

func mentorSessionSourceMissing(source domain.MentorSessionReader) bool {
	if source == nil {
		return true
	}
	v := reflect.ValueOf(source)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
