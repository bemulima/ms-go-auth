package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/tokenverify"
	"github.com/golang-jwt/jwt/v5"
)

type mentorStrictSessionStore struct {
	session  *domain.RefreshToken
	err      error
	calls    int
	hash     string
	deadline time.Duration
	after    func()
}

func (s *mentorStrictSessionStore) FindActive(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	s.calls++
	s.hash = hash
	if deadline, ok := ctx.Deadline(); ok {
		s.deadline = time.Until(deadline)
	}
	var result *domain.RefreshToken
	if s.session != nil {
		copy := *s.session
		result = &copy
	}
	if s.after != nil {
		s.after()
	}
	return result, s.err
}

type mentorStrictParser struct {
	parser tokenverify.Parser
	calls  int
	after  func()
}

func (p *mentorStrictParser) Parse(raw string) (*jwt.Token, jwt.MapClaims, error) {
	p.calls++
	token, claims, err := p.parser.Parse(raw)
	if p.after != nil {
		p.after()
	}
	return token, claims, err
}

func mentorStrictFixture(t *testing.T) (*MentorLiveSessionVerifier, *mentorStrictSessionStore, JWTSigner, string) {
	t.Helper()
	_, private, public := mentorTestKeys(t, 1)
	signer, err := NewJWTSigner(&config.Config{JWTPrivateKey: private, JWTPublicKey: public, JWTIssuer: "mentor-live-session-test", JWTAudience: "mentor-test-client"})
	if err != nil {
		t.Fatal("actual access signer setup failed")
	}
	store := &mentorStrictSessionStore{session: &domain.RefreshToken{UserID: mentorTestActor, RefreshTokenHash: hashToken(mentorTestSID), ExpiresAt: time.Now().Add(time.Hour)}}
	verifier, err := NewMentorLiveSessionVerifier(signer, store)
	if err != nil || verifier == nil {
		t.Fatal("strict current-session verifier setup failed")
	}
	token, err := signer.SignAccessToken(mentorTestActor, map[string]any{"sid": mentorTestSID, "role": "admin", "email": "unused@example.test"}, time.Minute)
	if err != nil {
		t.Fatal("actual access token setup failed")
	}
	return verifier, store, signer, token
}

func mentorHTTPAuthorityFixture(t *testing.T) (*MentorHTTPAuthority, *MentorLiveSessionVerifier, *mentorStrictSessionStore, *mentorAdminFixture, *mentorIntentFixture, string) {
	t.Helper()
	v, store, _, token := mentorStrictFixture(t)
	_, admins, intents := mentorFixtures()
	_, private, public := mentorTestKeys(t, 0)
	a, err := NewMentorHTTPAuthority(private, public, v, admins, intents)
	if err != nil || a == nil {
		t.Fatal("concrete authority setup failed")
	}
	return a, v, store, admins, intents, token
}

func TestMentorLiveSessionActualParserAndStoredBinding(t *testing.T) {
	v, store, _, token := mentorStrictFixture(t)
	result, err := v.VerifyToken(context.Background(), "must-not-be-logged", token)
	if err != nil || result == nil || result.UserID != mentorTestActor || result.Claims["sid"] != mentorTestSID || store.calls != 1 || store.hash != hashToken(mentorTestSID) {
		t.Fatal("actual verified session binding was not admitted")
	}
	if result.Email != "" || len(result.Claims) != 2 {
		t.Fatal("strict boundary leaked unnecessary verified claims")
	}
	if store.deadline <= 0 || store.deadline > 3*time.Second {
		t.Fatal("session read lacks bounded deadline")
	}
	store.session.RevokedAt = new(time.Time)
	if got, err := v.VerifyToken(context.Background(), "", token); got != nil || err != ErrMentorSessionUnauthenticated {
		t.Fatal("fresh read failed to reject revocation")
	}
}

func TestMentorLiveSessionInvalidTokensBeforeStore(t *testing.T) {
	cases := map[string]func(JWTSigner, string) string{
		"empty":               func(_ JWTSigner, _ string) string { return "" },
		"oversized":           func(_ JWTSigner, _ string) string { return strings.Repeat("a", 8193) },
		"header prefix":       func(_ JWTSigner, s string) string { return "Bearer " + s },
		"trailing whitespace": func(_ JWTSigner, s string) string { return s + " " },
		"tampered":            func(_ JWTSigner, s string) string { return s + "x" },
		"expired": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": mentorTestSID}, -time.Minute)
			return raw
		},
		"missing sid": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, nil, time.Minute)
			return raw
		},
		"null sid": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": nil}, time.Minute)
			return raw
		},
		"zero sid": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": "00000000-0000-0000-0000-000000000000"}, time.Minute)
			return raw
		},
		"noncanonical sid": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": strings.ReplaceAll(mentorTestSID, "-", "")}, time.Minute)
			return raw
		},
		"foreign purpose": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": mentorTestSID, "typ": "mentor_role_decision"}, time.Minute)
			return raw
		},
		"null purpose": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": mentorTestSID, "typ": nil}, time.Minute)
			return raw
		},
		"refresh": func(s JWTSigner, _ string) string {
			raw, _ := s.SignRefreshToken(mentorTestActor, mentorTestSID, time.Minute)
			return raw
		},
		"noncanonical sub": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken("not-a-canonical-user", map[string]any{"sid": mentorTestSID}, time.Minute)
			return raw
		},
		"fractional expiry": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": mentorTestSID, "exp": float64(time.Now().Add(time.Minute).Unix()) + 0.5}, time.Minute)
			return raw
		},
		"unsafe expiry": func(s JWTSigner, _ string) string {
			raw, _ := s.SignAccessToken(mentorTestActor, map[string]any{"sid": mentorTestSID, "exp": float64(9007199254740992)}, time.Minute)
			return raw
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v, store, signer, token := mentorStrictFixture(t)
			if result, err := v.VerifyToken(context.Background(), "", mutate(signer, token)); result != nil || err != ErrMentorSessionUnauthenticated || store.calls != 0 {
				t.Fatal("invalid access authority reached session store or wrong denial")
			}
		})
	}
}

func TestMentorLiveSessionPersistenceFailuresAndReturnBoundary(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*MentorLiveSessionVerifier, *mentorStrictSessionStore)
		want  error
	}{
		{"missing", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.session = nil
			s.err = domain.ErrNotFound
		}, ErrMentorSessionUnauthenticated},
		{"outage", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.err = errors.New("sensitive storage diagnostic")
		}, ErrMentorSessionUnavailable},
		{"mixed missing outage", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.err = errors.Join(domain.ErrNotFound, errors.New("outage"))
		}, ErrMentorSessionUnavailable},
		{"nil success", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) { s.session = nil }, ErrMentorSessionUnavailable},
		{"foreign hash", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.session.RefreshTokenHash = hashToken(mentorTestRequest)
		}, ErrMentorSessionUnavailable},
		{"foreign user", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) { s.session.UserID = mentorTestTarget }, ErrMentorSessionUnavailable},
		{"revoked", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			now := time.Now()
			s.session.RevokedAt = &now
		}, ErrMentorSessionUnauthenticated},
		{"expired session", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.session.ExpiresAt = time.Now().Add(-time.Second)
		}, ErrMentorSessionUnauthenticated},
		{"zero expiry", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) { s.session.ExpiresAt = time.Time{} }, ErrMentorSessionUnavailable},
		{"unsafe expiry", func(_ *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.session.ExpiresAt = time.Unix(9007199254740992, 0)
		}, ErrMentorSessionUnavailable},
		{"token expired during read", func(v *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.after = func() { v.clock = func() time.Time { return time.Now().Add(2 * time.Minute) } }
		}, ErrMentorSessionUnauthenticated},
		{"session expired during read", func(v *MentorLiveSessionVerifier, s *mentorStrictSessionStore) {
			s.session.ExpiresAt = time.Now().Add(time.Second)
			s.after = func() { v.clock = func() time.Time { return time.Now().Add(2 * time.Second) } }
		}, ErrMentorSessionUnauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, store, _, token := mentorStrictFixture(t)
			tc.alter(v, store)
			result, err := v.VerifyToken(context.Background(), "", token)
			if result != nil || err != tc.want || store.calls != 1 {
				t.Fatal("invalid persistence authority was not rejected with sanitized classification")
			}
		})
	}
}

func TestMentorLiveSessionConfigurationAndCancellation(t *testing.T) {
	v, store, signer, token := mentorStrictFixture(t)
	var nilParser *mentorStrictParser
	var nilReader *mentorStrictSessionStore
	for _, tc := range []struct {
		parser tokenverify.Parser
		reader domain.MentorSessionReader
	}{{nil, store}, {nilParser, store}, {signer, nil}, {signer, nilReader}} {
		if got, err := NewMentorLiveSessionVerifier(tc.parser, tc.reader); got != nil || err != ErrMentorSessionUnavailable {
			t.Fatal("invalid strict session configuration admitted")
		}
	}
	for _, bad := range []*MentorLiveSessionVerifier{nil, {}, {parser: signer, reader: store}} {
		if got, err := bad.VerifyToken(context.Background(), "", token); got != nil || err != ErrMentorSessionUnavailable {
			t.Fatal("unconfigured session verifier admitted")
		}
	}
	if got, err := v.VerifyToken(nil, "", token); got != nil || err != ErrMentorSessionUnavailable { //nolint:staticcheck // SA1012: explicitly test rejection of a nil context.
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := v.VerifyToken(ctx, "", token); got != nil || err != ErrMentorSessionUnavailable || store.calls != 0 {
		t.Fatal("cancelled request reached store")
	}
	ctx, cancel = context.WithCancel(context.Background())
	p := &mentorStrictParser{parser: signer, after: cancel}
	v.parser = p
	if got, err := v.VerifyToken(ctx, "", token); got != nil || err != ErrMentorSessionUnavailable || store.calls != 0 || p.calls != 1 {
		t.Fatal("cancellation after crypto did not stop store")
	}
	v.parser = signer
	ctx, cancel = context.WithCancel(context.Background())
	store.after = cancel
	if got, err := v.VerifyToken(ctx, "", token); got != nil || err != ErrMentorSessionUnavailable || store.calls != 1 {
		t.Fatal("cancellation after store did not stop success")
	}
	store.after = nil
	ctx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if got, err := v.VerifyToken(ctx, "", token); got == nil || err != nil || store.deadline > 100*time.Millisecond {
		t.Fatal("earlier deadline not preserved")
	}
}

func TestMentorHTTPAuthorityUserAndAdminSeparation(t *testing.T) {
	a, _, store, admins, intents, token := mentorHTTPAuthorityFixture(t)
	if actor, err := a.VerifyUser(context.Background(), token); actor != mentorTestActor || err != nil || store.calls != 1 || admins.calls != 0 || intents.calls != 0 {
		t.Fatal("user verification did not stay read-only and session-owned")
	}
	if actor, err := a.VerifyAdmin(context.Background(), token); actor != mentorTestActor || err != nil || store.calls != 3 || admins.calls != 1 || intents.calls != 0 {
		t.Fatal("Admin verification omitted exact owner or final session recheck")
	}
	admins.result.UniqueCanonicalDefaultAdmin = false
	if actor, err := a.VerifyAdmin(context.Background(), token); actor != "" || err != ErrMentorIdentityForbidden {
		t.Fatal("admin role claim substituted for current canonical owner authority")
	}
}

func TestMentorHTTPAuthorityAdminOwnerAndFinalSessionDenials(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*mentorStrictSessionStore, *mentorAdminFixture)
		want  error
		calls int
	}{
		{"owner deny", func(_ *mentorStrictSessionStore, a *mentorAdminFixture) { a.result.UniqueCanonicalDefaultAdmin = false }, ErrMentorIdentityForbidden, 1},
		{"foreign actor", func(_ *mentorStrictSessionStore, a *mentorAdminFixture) { a.result.ActorID = mentorTestTarget }, ErrMentorIdentityForbidden, 1},
		{"nil owner", func(_ *mentorStrictSessionStore, a *mentorAdminFixture) { a.result = nil }, ErrMentorIdentityForbidden, 1},
		{"owner unavailable", func(_ *mentorStrictSessionStore, a *mentorAdminFixture) { a.err = errors.New("private owner detail") }, ErrMentorSessionUnavailable, 1},
		{"revoked during owner read", func(s *mentorStrictSessionStore, a *mentorAdminFixture) {
			a.after = func() { now := time.Now(); s.session.RevokedAt = &now }
		}, ErrMentorSessionUnauthenticated, 2},
		{"store outage after owner", func(s *mentorStrictSessionStore, a *mentorAdminFixture) {
			a.after = func() { s.err = errors.New("private failure") }
		}, ErrMentorSessionUnavailable, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, store, admins, _, token := mentorHTTPAuthorityFixture(t)
			tc.alter(store, admins)
			actor, err := a.VerifyAdmin(context.Background(), token)
			if actor != "" || err != tc.want || store.calls != tc.calls {
				t.Fatal("Admin authority failure was not kept distinct and fail closed")
			}
		})
	}
}

func TestMentorHTTPAuthorityConcreteConfigurationAndIssue(t *testing.T) {
	a, _, store, admins, intents, token := mentorHTTPAuthorityFixture(t)
	proof, err := a.Issue(context.Background(), token, mentorTestRequestFor("APPROVE", 2))
	if proof == "" || err != nil || store.calls != 2 || admins.calls != 1 || intents.calls != 1 {
		t.Fatal("actual strict session and actual issuer were not composed")
	}
	claims := mentorDecodeClaims(t, proof, a.issuer)
	if string(claims["sub"]) != `"`+mentorTestActor+`"` {
		t.Fatal("wrong actor in actual issued proof")
	}
	_, private, public := mentorTestKeys(t, 0)
	if v, err := NewMentorHTTPAuthority(private, public, &MentorLiveSessionVerifier{}, admins, intents); v != nil || err == nil {
		t.Fatal("zero strict verifier accepted by production-style constructor")
	}
	for _, bad := range []*MentorHTTPAuthority{nil, {}} {
		if user, err := bad.VerifyUser(context.Background(), token); user != "" || err != ErrMentorSessionUnavailable {
			t.Fatal("zero authority accepted")
		}
		if user, err := bad.VerifyAdmin(context.Background(), token); user != "" || err != ErrMentorSessionUnavailable {
			t.Fatal("zero Admin authority accepted")
		}
		if proof, err := bad.Issue(context.Background(), token, mentorTestRequestFor("APPROVE", 2)); proof != "" || err != ErrMentorSessionUnavailable {
			t.Fatal("zero issuer accepted")
		}
	}
}

func TestMentorRoleDecisionRevalidatesSameSessionAfterOwners(t *testing.T) {
	for _, name := range []string{"revoked", "changed actor", "changed sid", "unavailable", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			issuer, sessions, _, intents := mentorIssuerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			intents.after = func() {
				switch name {
				case "revoked":
					sessions.err = ErrMentorSessionUnauthenticated
				case "changed actor":
					sessions.result.UserID = mentorTestTarget
				case "changed sid":
					sessions.result.Claims["sid"] = mentorTestRequest
				case "unavailable":
					sessions.err = ErrMentorSessionUnavailable
				case "cancelled":
					cancel()
				}
			}
			proof, err := issuer.Issue(ctx, "", "current-session", mentorTestRequestFor("APPROVE", 2))
			if proof != "" || err == nil {
				t.Fatal("changed session survived delayed owner confirmations")
			}
			if name != "cancelled" && sessions.calls != 2 {
				t.Fatal("same bearer was not revalidated after owners")
			}
			if name == "unavailable" && err != ErrMentorRoleDecisionUnavailable {
				t.Fatal("session dependency outage was misreported as denied")
			}
		})
	}
}

func TestMentorRoleDecisionTypedSessionErrors(t *testing.T) {
	for _, tc := range []struct {
		name         string
		source, want error
	}{{"unavailable", ErrMentorSessionUnavailable, ErrMentorRoleDecisionUnavailable}, {"unauthenticated", ErrMentorSessionUnauthenticated, ErrMentorSessionUnauthenticated}, {"unknown legacy", errors.New("legacy private detail"), ErrMentorRoleDecisionDenied}} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, sessions, admins, intents := mentorIssuerFixture(t)
			sessions.err = tc.source
			proof, err := issuer.Issue(context.Background(), "", "current-session", mentorTestRequestFor("APPROVE", 2))
			if proof != "" || err != tc.want || admins.calls+intents.calls != 0 {
				t.Fatal("typed strict session failure not preserved or leaked dependency detail")
			}
		})
	}
}

func TestMentorRoleDecisionFinalSigningClock(t *testing.T) {
	for _, name := range []string{"expired while signing", "clock moved backwards"} {
		t.Run(name, func(t *testing.T) {
			issuer, _, _, _ := mentorIssuerFixture(t)
			calls := 0
			issuer.clock = func() time.Time {
				calls++
				if calls == 1 {
					return time.Unix(1_800_000_000, 0)
				}
				if name == "clock moved backwards" {
					return time.Unix(1_799_999_999, 0)
				}
				return time.Unix(1_800_000_030, 0)
			}
			proof, err := issuer.Issue(context.Background(), "", "current-session", mentorTestRequestFor("APPROVE", 2))
			if proof != "" || err != ErrMentorRoleDecisionUnavailable || calls != 2 {
				t.Fatal("expired/backwards signed assertion was returned")
			}
		})
	}
}
