package domain

import (
	"context"
	"errors"
)

// ErrMentorSessionUnavailable is deliberately credential- and storage-neutral.
var ErrMentorSessionUnavailable = errors.New("mentor session authority unavailable")

const MentorSessionMaxTokenBytes = 8192

// ValidMentorAccessToken checks only the bounded opaque bearer-token syntax.
// It does not authenticate a token or authorize a principal.
func ValidMentorAccessToken(raw string) bool {
	if len(raw) == 0 || len(raw) > MentorSessionMaxTokenBytes {
		return false
	}
	padding := false
	for i := range raw {
		c := raw[i]
		if c == '=' {
			if i == 0 {
				return false
			}
			padding = true
			continue
		}
		if padding || !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
			c == '~' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

// MentorSessionReader is the Auth-owned active persisted-session boundary.
// Known absence is ErrNotFound; every other error is an unavailable authority.
// Auth's existing RefreshTokenHash lookup encoding is rt:<canonical sid>, not a
// new hash algorithm. The caller validates key, principal, revocation and expiry.
type MentorSessionReader interface {
	FindActive(context.Context, string) (*RefreshToken, error)
}
