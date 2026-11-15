package usecase

import (
	"context"
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
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

const (
	mentorTestActor   = "11111111-1111-4111-8111-111111111111"
	mentorTestTarget  = "22222222-2222-4222-8222-222222222222"
	mentorTestApp     = "33333333-3333-4333-8333-333333333333"
	mentorTestRequest = "44444444-4444-4444-8444-444444444444"
	mentorTestSID     = "55555555-5555-4555-8555-555555555555"
)

var mentorEphemeralKeys struct {
	sync.Once
	keys [2]*rsa.PrivateKey
	err  error
}

func mentorTestKeys(t *testing.T, index int) (*rsa.PrivateKey, string, string) {
	t.Helper()
	mentorEphemeralKeys.Do(func() {
		for i := range mentorEphemeralKeys.keys {
			mentorEphemeralKeys.keys[i], mentorEphemeralKeys.err = rsa.GenerateKey(rand.Reader, 2048)
			if mentorEphemeralKeys.err != nil {
				return
			}
		}
	})
	if mentorEphemeralKeys.err != nil {
		t.Fatal("ephemeral key generation failed")
	}
	key := mentorEphemeralKeys.keys[index]
	privatePEM, publicPEM := mentorTestPEM(key)
	return key, privatePEM, publicPEM
}

func mentorTestPEM(key *rsa.PrivateKey) (string, string) {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
}

func mentorTestDigest(actor, decision, app, request string, revision int64) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{decision, actor, app, request, strconv.FormatInt(revision-1, 10)}, "|")))
	return hex.EncodeToString(sum[:])
}

func mentorTestRequestFor(decision string, revision int64) domain.MentorRoleDecisionRequest {
	return domain.MentorRoleDecisionRequest{
		TargetUserID: mentorTestTarget, ApplicationID: mentorTestApp, ApplicationRevision: revision,
		Decision: decision, RequestID: mentorTestRequest,
		DecisionDigest: mentorTestDigest(mentorTestActor, decision, mentorTestApp, mentorTestRequest, revision),
	}
}

type mentorSessionFixture struct {
	result *VerificationResult
	err    error
	calls  int
	after  func()
}

func (f *mentorSessionFixture) VerifyToken(_ context.Context, _, _ string) (*VerificationResult, error) {
	f.calls++
	if f.after != nil {
		f.after()
	}
	return f.result, f.err
}

type mentorAdminFixture struct {
	result *domain.CanonicalAdminConfirmation
	err    error
	calls  int
	actor  string
	after  func()
}

func (f *mentorAdminFixture) ConfirmCanonicalAdmin(_ context.Context, actor string) (*domain.CanonicalAdminConfirmation, error) {
	f.calls++
	f.actor = actor
	if f.after != nil {
		f.after()
	}
	return f.result, f.err
}

type mentorIntentFixture struct {
	err    error
	calls  int
	seen   domain.MentorRoleDecisionBinding
	nil    bool
	mutate func(*domain.MentorCommittedIntentConfirmation)
	after  func()
}

func (f *mentorIntentFixture) ConfirmCommittedMentorIntent(_ context.Context, binding domain.MentorRoleDecisionBinding) (*domain.MentorCommittedIntentConfirmation, error) {
	f.calls++
	f.seen = binding
	if f.after != nil {
		f.after()
	}
	if f.nil || f.err != nil {
		return nil, f.err
	}
	state := domain.MentorApprovalPendingGrant
	if binding.Decision == "SUSPEND" {
		state = domain.MentorSuspended
	}
	result := &domain.MentorCommittedIntentConfirmation{Binding: binding, Committed: true, Current: true, State: state}
	if f.mutate != nil {
		f.mutate(result)
	}
	return result, nil
}

func mentorFixtures() (*mentorSessionFixture, *mentorAdminFixture, *mentorIntentFixture) {
	return &mentorSessionFixture{result: &VerificationResult{UserID: mentorTestActor, Claims: map[string]any{"sid": mentorTestSID}}},
		&mentorAdminFixture{result: &domain.CanonicalAdminConfirmation{ActorID: mentorTestActor, UniqueCanonicalDefaultAdmin: true}},
		&mentorIntentFixture{}
}

func mentorIssuerFixture(t *testing.T) (*MentorRoleDecisionIssuer, *mentorSessionFixture, *mentorAdminFixture, *mentorIntentFixture) {
	t.Helper()
	_, privatePEM, publicPEM := mentorTestKeys(t, 0)
	sessions, admins, intents := mentorFixtures()
	issuer, err := NewMentorRoleDecisionIssuer(privatePEM, publicPEM, sessions, admins, intents)
	if err != nil || issuer == nil {
		t.Fatal("valid dedicated keys and mandatory owner ports must construct issuer")
	}
	issuer.clock = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return issuer, sessions, admins, intents
}

func mentorDecodeClaims(t *testing.T, raw string, issuer *MentorRoleDecisionIssuer) map[string]json.RawMessage {
	t.Helper()
	key, _, _ := mentorTestKeys(t, 0)
	token, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 || !reflect.DeepEqual(token.Header, map[string]any{"alg": "RS256", "typ": "JWT"}) {
			t.Fatal("unexpected Mentor proof header")
		}
		return &key.PublicKey, nil
	}, jwt.WithIssuer(domain.MentorRoleDecisionIssuer), jwt.WithAudience(domain.MentorRoleDecisionAudience), jwt.WithTimeFunc(issuer.clock), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || token == nil || !token.Valid {
		t.Fatal("Mentor proof did not verify with the dedicated public key")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > domain.MentorRoleDecisionMaxBytes {
		t.Fatal("invalid compact proof size or segments")
	}
	for _, part := range parts {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != part {
			t.Fatal("proof segment is not canonical unpadded base64url")
		}
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || len(claims) != 16 {
		t.Fatal("Mentor proof must contain exactly 16 claims")
	}
	return claims
}

func TestMentorRoleDecisionExactSignedClaims(t *testing.T) {
	for _, pair := range []struct {
		decision string
		revision int64
	}{{"APPROVE", 2}, {"SUSPEND", 3}, {"SUSPEND", 4}} {
		t.Run(fmt.Sprintf("%s%d", pair.decision, pair.revision), func(t *testing.T) {
			issuer, sessions, admins, intents := mentorIssuerFixture(t)
			request := mentorTestRequestFor(pair.decision, pair.revision)
			raw, err := issuer.Issue(context.Background(), "trace", "session-presented-to-owner", request)
			if err != nil || raw == "" {
				t.Fatal("committed current authorized decision must produce a signed assertion")
			}
			claims := mentorDecodeClaims(t, raw, issuer)
			for name, want := range map[string]string{
				"iss": domain.MentorRoleDecisionIssuer, "aud": domain.MentorRoleDecisionAudience, "sub": mentorTestActor,
				"typ": domain.MentorRoleDecisionType, "purpose": domain.MentorRoleDecisionPurpose,
				"target_user_id": request.TargetUserID, "application_id": request.ApplicationID, "decision": request.Decision,
				"request_id": request.RequestID, "decision_digest": request.DecisionDigest,
				"role": domain.MentorRoleDecisionRole, "service": domain.MentorRoleDecisionService,
			} {
				var got string
				if json.Unmarshal(claims[name], &got) != nil || got != want {
					t.Fatalf("claim %s is not the exact bound value", name)
				}
			}
			for name, want := range map[string]int64{"iat": issuer.clock().Unix(), "exp": issuer.clock().Unix() + 30, "application_revision": pair.revision} {
				if string(claims[name]) != strconv.FormatInt(want, 10) {
					t.Fatalf("claim %s must be an exact integer", name)
				}
			}
			var jti string
			if json.Unmarshal(claims["jti"], &jti) != nil || !canonicalReviewerUUID(jti) {
				t.Fatal("fresh canonical nonzero JTI required")
			}
			if sessions.calls != 1 || admins.calls != 1 || intents.calls != 1 || admins.actor != mentorTestActor ||
				intents.seen != (domain.MentorRoleDecisionBinding{MentorRoleDecisionRequest: request, AdminActorID: mentorTestActor}) {
				t.Fatal("issuance did not check each exact owner binding")
			}
		})
	}
}

func TestMentorRoleDecisionFreshSessionAndJTIEveryRetry(t *testing.T) {
	issuer, sessions, admins, intents := mentorIssuerFixture(t)
	request := mentorTestRequestFor("APPROVE", 2)
	first, err := issuer.Issue(context.Background(), "trace", "first-session", request)
	if err != nil {
		t.Fatal("first authorized attempt failed")
	}
	second, err := issuer.Issue(context.Background(), "trace", "fresh-session", request)
	if err != nil {
		t.Fatal("same-command authorized retry failed")
	}
	one, two := mentorDecodeClaims(t, first, issuer), mentorDecodeClaims(t, second, issuer)
	if string(one["jti"]) == string(two["jti"]) || string(one["request_id"]) != string(two["request_id"]) || sessions.calls != 2 || admins.calls != 2 || intents.calls != 2 {
		t.Fatal("retry must reauthenticate all owners, preserve command and generate a new JTI")
	}
	sessions.err = errors.New("revoked session")
	raw, err := issuer.Issue(context.Background(), "trace", "revoked-session", request)
	if raw != "" || !errors.Is(err, ErrMentorRoleDecisionDenied) || sessions.calls != 3 || admins.calls != 2 || intents.calls != 2 {
		t.Fatal("previous successful issuance must not bypass the current session")
	}
}

func TestMentorRoleDecisionSessionAndAdminDenials(t *testing.T) {
	for name, mutate := range map[string]func(*mentorSessionFixture, *mentorAdminFixture){
		"session failure":     func(s *mentorSessionFixture, _ *mentorAdminFixture) { s.err = errors.New("unavailable or revoked") },
		"missing session":     func(s *mentorSessionFixture, _ *mentorAdminFixture) { s.result = nil },
		"noncanonical actor":  func(s *mentorSessionFixture, _ *mentorAdminFixture) { s.result.UserID = "not-an-actor" },
		"stateless access":    func(s *mentorSessionFixture, _ *mentorAdminFixture) { delete(s.result.Claims, "sid") },
		"mistyped session ID": func(s *mentorSessionFixture, _ *mentorAdminFixture) { s.result.Claims["sid"] = 1 },
		"nil session ID": func(s *mentorSessionFixture, _ *mentorAdminFixture) {
			s.result.Claims["sid"] = "00000000-0000-0000-0000-000000000000"
		},
		"refresh token": func(s *mentorSessionFixture, _ *mentorAdminFixture) { s.result.Claims["typ"] = "refresh" },
		"assertion token": func(s *mentorSessionFixture, _ *mentorAdminFixture) {
			s.result.Claims["typ"] = domain.MentorRoleDecisionType
		},
		"stored other actor":   func(s *mentorSessionFixture, _ *mentorAdminFixture) { s.result.UserID = mentorTestTarget },
		"not canonical admin":  func(_ *mentorSessionFixture, a *mentorAdminFixture) { a.result.UniqueCanonicalDefaultAdmin = false },
		"missing admin result": func(_ *mentorSessionFixture, a *mentorAdminFixture) { a.result = nil },
		"foreign admin result": func(_ *mentorSessionFixture, a *mentorAdminFixture) { a.result.ActorID = mentorTestTarget },
		"unavailable admin":    func(_ *mentorSessionFixture, a *mentorAdminFixture) { a.err = errors.New("offline") },
	} {
		t.Run(name, func(t *testing.T) {
			issuer, sessions, admins, intents := mentorIssuerFixture(t)
			sessions.result.Claims["role"] = "admin" // signed role claim is not canonical owner authority.
			mutate(sessions, admins)
			raw, err := issuer.Issue(context.Background(), "trace", "presented-session", mentorTestRequestFor("APPROVE", 2))
			if raw != "" || err == nil || intents.calls != 0 {
				t.Fatal("denied or mismatched authority reached Mentor or produced assertion")
			}
		})
	}
}

func TestMentorRoleDecisionIntentMustBeExactCurrentCommittedState(t *testing.T) {
	for name, mutate := range map[string]func(*domain.MentorCommittedIntentConfirmation){
		"actor":            func(c *domain.MentorCommittedIntentConfirmation) { c.Binding.AdminActorID = mentorTestTarget },
		"target":           func(c *domain.MentorCommittedIntentConfirmation) { c.Binding.TargetUserID = mentorTestActor },
		"application":      func(c *domain.MentorCommittedIntentConfirmation) { c.Binding.ApplicationID = mentorTestTarget },
		"revision":         func(c *domain.MentorCommittedIntentConfirmation) { c.Binding.ApplicationRevision++ },
		"request":          func(c *domain.MentorCommittedIntentConfirmation) { c.Binding.RequestID = mentorTestTarget },
		"decision":         func(c *domain.MentorCommittedIntentConfirmation) { c.Binding.Decision = "SUSPEND" },
		"digest":           func(c *domain.MentorCommittedIntentConfirmation) { c.Binding.DecisionDigest = strings.Repeat("a", 64) },
		"not committed":    func(c *domain.MentorCommittedIntentConfirmation) { c.Committed = false },
		"stale":            func(c *domain.MentorCommittedIntentConfirmation) { c.Current = false },
		"already approved": func(c *domain.MentorCommittedIntentConfirmation) { c.State = "APPROVED" },
		"suspended":        func(c *domain.MentorCommittedIntentConfirmation) { c.State = domain.MentorSuspended },
		"unknown state":    func(c *domain.MentorCommittedIntentConfirmation) { c.State = "" },
	} {
		t.Run(name, func(t *testing.T) {
			issuer, _, _, intents := mentorIssuerFixture(t)
			intents.mutate = mutate
			raw, err := issuer.Issue(context.Background(), "trace", "presented-session", mentorTestRequestFor("APPROVE", 2))
			if raw != "" || !errors.Is(err, ErrMentorRoleDecisionDenied) || intents.calls != 1 {
				t.Fatal("unbound, stale or incompatible Mentor intent must deny")
			}
		})
	}
	for _, unavailable := range []bool{false, true} {
		issuer, _, _, intents := mentorIssuerFixture(t)
		intents.nil = true
		if unavailable {
			intents.err = errors.New("owner unavailable")
		}
		if raw, err := issuer.Issue(context.Background(), "trace", "presented-session", mentorTestRequestFor("APPROVE", 2)); raw != "" || err == nil {
			t.Fatal("missing or unavailable Mentor confirmation must deny")
		}
	}
	issuer, _, _, intents := mentorIssuerFixture(t)
	intents.mutate = func(c *domain.MentorCommittedIntentConfirmation) { c.State = domain.MentorApprovalPendingGrant }
	if raw, err := issuer.Issue(context.Background(), "trace", "presented-session", mentorTestRequestFor("SUSPEND", 4)); raw != "" || err == nil {
		t.Fatal("suspension must require current suspended state")
	}
}

func TestMentorRoleDecisionMalformedRequestFailsBeforeOwners(t *testing.T) {
	for name, mutate := range map[string]func(*domain.MentorRoleDecisionRequest){
		"missing target":             func(r *domain.MentorRoleDecisionRequest) { r.TargetUserID = "" },
		"zero target":                func(r *domain.MentorRoleDecisionRequest) { r.TargetUserID = "00000000-0000-0000-0000-000000000000" },
		"uppercase application":      func(r *domain.MentorRoleDecisionRequest) { r.ApplicationID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
		"unhyphenated request":       func(r *domain.MentorRoleDecisionRequest) { r.RequestID = strings.ReplaceAll(r.RequestID, "-", "") },
		"spaced target":              func(r *domain.MentorRoleDecisionRequest) { r.TargetUserID += " " },
		"unknown decision":           func(r *domain.MentorRoleDecisionRequest) { r.Decision = "REJECT" },
		"lowercase decision":         func(r *domain.MentorRoleDecisionRequest) { r.Decision = "approve" },
		"negative revision":          func(r *domain.MentorRoleDecisionRequest) { r.ApplicationRevision = -1 },
		"uncommitted revision":       func(r *domain.MentorRoleDecisionRequest) { r.ApplicationRevision = 1 },
		"finalized approve revision": func(r *domain.MentorRoleDecisionRequest) { r.ApplicationRevision = 3 },
		"suspend revision two":       func(r *domain.MentorRoleDecisionRequest) { r.Decision = "SUSPEND" },
		"missing digest":             func(r *domain.MentorRoleDecisionRequest) { r.DecisionDigest = "" },
		"uppercase digest":           func(r *domain.MentorRoleDecisionRequest) { r.DecisionDigest = strings.ToUpper(r.DecisionDigest) },
	} {
		t.Run(name, func(t *testing.T) {
			issuer, sessions, admins, intents := mentorIssuerFixture(t)
			request := mentorTestRequestFor("APPROVE", 2)
			mutate(&request)
			if raw, err := issuer.Issue(context.Background(), "trace", "presented-session", request); raw != "" || !errors.Is(err, ErrMentorRoleDecisionInvalid) || sessions.calls+admins.calls+intents.calls != 0 {
				t.Fatal("malformed request reached authority or produced assertion")
			}
		})
	}
	issuer, _, admins, intents := mentorIssuerFixture(t)
	request := mentorTestRequestFor("APPROVE", 2)
	request.DecisionDigest = mentorTestDigest(mentorTestTarget, request.Decision, request.ApplicationID, request.RequestID, request.ApplicationRevision)
	if raw, err := issuer.Issue(context.Background(), "trace", "presented-session", request); raw != "" || !errors.Is(err, ErrMentorRoleDecisionInvalid) || admins.calls+intents.calls != 0 {
		t.Fatal("digest for another actor must not reach external authority")
	}
}

func TestMentorRoleDecisionConfigurationFailsClosed(t *testing.T) {
	_, privatePEM, publicPEM := mentorTestKeys(t, 0)
	_, _, otherPublic := mentorTestKeys(t, 1)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("test-only weak key generation failed")
	}
	weakPrivate, weakPublic := mentorTestPEM(weak)
	for name, pair := range map[string][2]string{
		"empty": {"", ""}, "missing private": {"", publicPEM}, "missing public": {privatePEM, ""},
		"mismatched": {privatePEM, otherPublic}, "weak": {weakPrivate, weakPublic},
		"invalid private": {"invalid", publicPEM}, "invalid public": {privatePEM, "invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			s, a, m := mentorFixtures()
			issuer, err := NewMentorRoleDecisionIssuer(pair[0], pair[1], s, a, m)
			if issuer != nil || !errors.Is(err, ErrMentorRoleDecisionUnavailable) {
				t.Fatal("missing, weak or incompatible keys must disable issuer")
			}
		})
	}
	for _, missing := range []string{"session", "admin", "intent", "typed session", "typed admin", "typed intent"} {
		t.Run(missing, func(t *testing.T) {
			s, a, m := mentorFixtures()
			var session MentorSessionVerifier = s
			var admin domain.CanonicalAdminVerifier = a
			var intent domain.MentorCommittedIntentVerifier = m
			switch missing {
			case "session":
				session = nil
			case "admin":
				admin = nil
			case "intent":
				intent = nil
			case "typed session":
				session = (*mentorSessionFixture)(nil)
			case "typed admin":
				admin = (*mentorAdminFixture)(nil)
			case "typed intent":
				intent = (*mentorIntentFixture)(nil)
			}
			if issuer, err := NewMentorRoleDecisionIssuer(privatePEM, publicPEM, session, admin, intent); issuer != nil || !errors.Is(err, ErrMentorRoleDecisionUnavailable) {
				t.Fatal("all authenticated owner ports must be present")
			}
		})
	}
	for _, issuer := range []*MentorRoleDecisionIssuer{nil, {}} {
		if raw, err := issuer.Issue(context.Background(), "trace", "session", mentorTestRequestFor("APPROVE", 2)); raw != "" || !errors.Is(err, ErrMentorRoleDecisionUnavailable) {
			t.Fatal("nil or zero issuer must fail closed")
		}
	}
}

func TestMentorRoleDecisionCancellationStopsIssuance(t *testing.T) {
	for _, stage := range []string{"before", "session", "admin", "intent"} {
		t.Run(stage, func(t *testing.T) {
			issuer, sessions, admins, intents := mentorIssuerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "before":
				cancel()
			case "session":
				sessions.after = cancel
			case "admin":
				admins.after = cancel
			case "intent":
				intents.after = cancel
			}
			if raw, err := issuer.Issue(ctx, "trace", "session", mentorTestRequestFor("APPROVE", 2)); raw != "" || !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation must return no assertion")
			}
			if stage == "before" && sessions.calls != 0 || stage == "session" && admins.calls != 0 || stage == "admin" && intents.calls != 0 {
				t.Fatal("cancelled invocation continued to another authority")
			}
		})
	}
}

func TestMentorRoleDecisionRejectsUnsafeClockAndEmptyBearer(t *testing.T) {
	for _, seconds := range []int64{-1, 0, domain.MentorRoleDecisionMaxInteger - 29, domain.MentorRoleDecisionMaxInteger} {
		issuer, _, _, _ := mentorIssuerFixture(t)
		issuer.clock = func() time.Time { return time.Unix(seconds, 0) }
		if raw, err := issuer.Issue(context.Background(), "trace", "session", mentorTestRequestFor("APPROVE", 2)); raw != "" || err == nil {
			t.Fatal("unsafe or nonpositive timestamp must not issue assertion")
		}
	}
	issuer, sessions, _, _ := mentorIssuerFixture(t)
	if raw, err := issuer.Issue(context.Background(), "trace", "", mentorTestRequestFor("APPROVE", 2)); raw != "" || err == nil || sessions.calls != 0 {
		t.Fatal("missing live bearer must fail before session owner")
	}
}

// This fixture replaces persistence only. The existing authService and actual
// access-token signer/verifier execute, including hashed-sid ownership checks.
type mentorLiveSessionStore struct {
	domain.RefreshTokenRepository
	userID  string
	revoked bool
	calls   int
}

func (f *mentorLiveSessionStore) FindActive(_ context.Context, hash string) (*domain.RefreshToken, error) {
	f.calls++
	if f.revoked || hash != hashToken(mentorTestSID) {
		return nil, domain.ErrNotFound
	}
	return &domain.RefreshToken{UserID: f.userID, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestMentorRoleDecisionUsesExistingCurrentAuthSession(t *testing.T) {
	_, accessPrivate, accessPublic := mentorTestKeys(t, 1)
	cfg := &config.Config{JWTPrivateKey: accessPrivate, JWTPublicKey: accessPublic, JWTIssuer: "session-test", JWTAudience: "session-client"}
	signer, err := NewJWTSigner(cfg)
	if err != nil {
		t.Fatal("access signer setup failed")
	}
	store := &mentorLiveSessionStore{userID: mentorTestActor}
	sessions := &authService{signer: signer, refresh: store, logger: zerolog.New(io.Discard)}
	_, admins, intents := mentorFixtures()
	_, privatePEM, publicPEM := mentorTestKeys(t, 0)
	issuer, err := NewMentorRoleDecisionIssuer(privatePEM, publicPEM, sessions, admins, intents)
	if err != nil || issuer == nil {
		t.Fatal("existing Auth service must satisfy live session port")
	}
	bearer, err := signer.SignAccessToken(mentorTestActor, map[string]any{"sid": mentorTestSID}, time.Minute)
	if err != nil {
		t.Fatal("access token setup failed")
	}
	if raw, err := issuer.Issue(context.Background(), "test", bearer, mentorTestRequestFor("APPROVE", 2)); raw == "" || err != nil || store.calls != 1 {
		t.Fatal("active persisted Auth session did not authorize source issuance")
	}
	store.revoked = true
	if raw, err := issuer.Issue(context.Background(), "test", bearer, mentorTestRequestFor("APPROVE", 2)); raw != "" || !errors.Is(err, ErrMentorRoleDecisionDenied) || store.calls != 2 || admins.calls != 1 {
		t.Fatal("revoked persisted session must deny without new Admin lookup")
	}
	store.revoked = false
	store.userID = mentorTestTarget
	if raw, err := issuer.Issue(context.Background(), "test", bearer, mentorTestRequestFor("APPROVE", 2)); raw != "" || err == nil {
		t.Fatal("session belonging to another user must deny")
	}
	stateless, err := signer.SignAccessToken(mentorTestActor, nil, time.Minute)
	if err != nil {
		t.Fatal("stateless compatibility token setup failed")
	}
	if raw, err := issuer.Issue(context.Background(), "test", stateless, mentorTestRequestFor("APPROVE", 2)); raw != "" || err == nil {
		t.Fatal("legacy stateless token must not authorize new Mentor decision")
	}
}
