package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/auth-service/config"
	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	internalhttp "github.com/example/auth-service/internal/transport/http/private"
	"github.com/example/auth-service/internal/usecase"
	"github.com/golang-jwt/jwt/v5"
	nats "github.com/nats-io/nats.go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	compositionActor   = "11111111-1111-4111-8111-111111111111"
	compositionTarget  = "22222222-2222-4222-8222-222222222222"
	compositionApp     = "33333333-3333-4333-8333-333333333333"
	compositionRequest = "44444444-4444-4444-8444-444444444444"
	compositionSID     = "55555555-5555-4555-8555-555555555555"
)

var compositionTestKeys struct {
	sync.Once
	keys [5]*rsa.PrivateKey
	err  error
}

func compositionKey(t *testing.T, index int) (*rsa.PrivateKey, MentorCompositionKeyPair) {
	t.Helper()
	compositionTestKeys.Do(func() {
		for i := range compositionTestKeys.keys {
			compositionTestKeys.keys[i], compositionTestKeys.err = rsa.GenerateKey(rand.Reader, 2048)
			if compositionTestKeys.err != nil {
				return
			}
		}
	})
	if compositionTestKeys.err != nil {
		t.Fatal("ephemeral composition keys unavailable")
	}
	key := compositionTestKeys.keys[index]
	return key, MentorCompositionKeyPair{
		PrivatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		PublicPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})),
	}
}

// The SQL transport is controlled; the production GORM PostgreSQL reader and
// refresh repository still execute. No PostgreSQL engine, listener or daemon
// is involved, and the fixture forbids writes and transaction startup.
type compositionSQL struct {
	connects int
	queries  int
	active   bool
	err      error
}

type compositionConnector struct{ fixture *compositionSQL }

func (c compositionConnector) Connect(context.Context) (driver.Conn, error) {
	c.fixture.connects++
	return compositionSQLConn{c.fixture}, nil
}
func (c compositionConnector) Driver() driver.Driver { return compositionDriver{c.fixture} }

type compositionDriver struct{ fixture *compositionSQL }

func (d compositionDriver) Open(string) (driver.Conn, error) {
	return compositionConnector{d.fixture}.Connect(context.Background())
}

type compositionSQLConn struct{ fixture *compositionSQL }

func (compositionSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared statement")
}
func (compositionSQLConn) Close() error { return nil }
func (compositionSQLConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c compositionSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.fixture.queries++
	if !strings.Contains(query, "auth_refresh_token") || !strings.Contains(query, "revoked_at IS NULL") ||
		!strings.Contains(query, "expires_at >") || len(args) < 2 || args[0].Value != "rt:"+compositionSID {
		return nil, errors.New("unexpected session lookup")
	}
	if c.fixture.err != nil {
		return nil, c.fixture.err
	}
	return &compositionRows{present: c.fixture.active}, nil
}

type compositionRows struct{ present bool }

func (*compositionRows) Columns() []string {
	return []string{"id", "user_id", "refresh_token_hash", "expires_at", "revoked_at"}
}
func (*compositionRows) Close() error { return nil }
func (r *compositionRows) Next(values []driver.Value) error {
	if !r.present {
		return io.EOF
	}
	r.present = false
	copy(values, []driver.Value{compositionApp, compositionActor, "rt:" + compositionSID, time.Now().Add(time.Hour), nil})
	return nil
}

// Only the two signed owner replies are fixtures. The actual owner client
// creates the lookup signatures and authenticates these nonce-bound responses.
type compositionRequester struct {
	lookupKey, adminKey, intentKey *rsa.PrivateKey
	adminCalls, intentCalls        int
	err                            error
}

func (r *compositionRequester) RequestWithContext(_ context.Context, subject string, body []byte) (*nats.Msg, error) {
	if r == nil {
		panic("typed-nil requester invoked")
	}
	var replyKey *rsa.PrivateKey
	var issuer, audience, kind, purpose string
	switch subject {
	case natsadapter.MentorCanonicalAdminLookupSubject:
		r.adminCalls++
		replyKey, issuer = r.adminKey, "ms-go-rbac"
		audience, kind, purpose = "ms-go-auth-mentor-canonical-admin-decision", "mentor_canonical_admin_decision", "RBAC_AUTH_MENTOR_CANONICAL_ADMIN_DECISION_V1"
	case natsadapter.MentorCommittedIntentLookupSubject:
		r.intentCalls++
		replyKey, issuer = r.intentKey, "ms-go-mentor"
		audience, kind, purpose = "ms-go-auth-mentor-committed-role-intent-decision", "mentor_committed_role_intent_decision", "MENTOR_AUTH_COMMITTED_ROLE_INTENT_DECISION_V1"
	default:
		return nil, errors.New("unexpected owner subject")
	}
	if r.err != nil {
		return nil, r.err
	}
	var envelope map[string]string
	if json.Unmarshal(body, &envelope) != nil || len(envelope) != 1 || envelope["proof"] == "" {
		return nil, errors.New("unexpected owner envelope")
	}
	request, err := jwt.Parse(envelope["proof"], func(*jwt.Token) (any, error) { return &r.lookupKey.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !request.Valid {
		return nil, errors.New("unverified owner request")
	}
	claims := request.Claims.(jwt.MapClaims)
	if claims["sub"] != compositionActor || claims["subject"] != subject {
		return nil, errors.New("incorrect owner request binding")
	}
	nonce, err := usecase.GenerateJTI()
	if err != nil {
		return nil, errors.New("fixture nonce unavailable")
	}
	now := time.Now().Unix()
	expiry := now + 15
	if requestExpiry := int64(claims["exp"].(float64)); requestExpiry < expiry {
		expiry = requestExpiry
	}
	digest := sha256.Sum256([]byte(envelope["proof"]))
	reply := jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": compositionActor, "typ": kind, "purpose": purpose,
		"subject": subject, "jti": nonce, "iat": now, "exp": expiry,
		"request_jti": claims["jti"], "request_digest": hex.EncodeToString(digest[:]),
	}
	if subject == natsadapter.MentorCanonicalAdminLookupSubject {
		reply["decision"] = "ALLOW"
	} else {
		for _, key := range []string{"target_user_id", "application_id", "application_revision", "decision", "request_id", "decision_digest"} {
			reply[key] = claims[key]
		}
		reply["result"], reply["state"] = "ALLOW", "APPROVAL_PENDING_GRANT"
	}
	proof, err := jwt.NewWithClaims(jwt.SigningMethodRS256, reply).SignedString(replyKey)
	if err != nil {
		return nil, errors.New("fixture reply unavailable")
	}
	raw, err := json.Marshal(map[string]string{"decision_jwt": proof})
	return &nats.Msg{Data: raw}, err
}

type compositionNilParser struct{}

func (*compositionNilParser) Parse(string) (*jwt.Token, jwt.MapClaims, error) {
	panic("typed-nil parser invoked")
}

func compositionFixture(t *testing.T) (MentorCompositionConfig, MentorCompositionDependencies, *compositionSQL, *compositionRequester, string) {
	t.Helper()
	_, access := compositionKey(t, 0)
	_, role := compositionKey(t, 1)
	lookupKey, lookup := compositionKey(t, 2)
	adminKey, admin := compositionKey(t, 3)
	intentKey, intent := compositionKey(t, 4)
	signer, err := usecase.NewJWTSigner(&config.Config{JWTPrivateKey: access.PrivatePEM, JWTPublicKey: access.PublicPEM, JWTIssuer: "composition-source", JWTAudience: "composition-client"})
	if err != nil {
		t.Fatal("actual access parser unavailable")
	}
	session := &compositionSQL{active: true}
	db := sql.OpenDB(compositionConnector{session})
	t.Cleanup(func() { _ = db.Close() })
	gdb, err := gorm.Open(postgres.New(postgres.Config{Conn: db, PreferSimpleProtocol: true}), &gorm.Config{DisableAutomaticPing: true, SkipDefaultTransaction: true, Logger: logger.Discard})
	if err != nil {
		t.Fatal("controlled owner SQL unavailable")
	}
	owners := &compositionRequester{lookupKey: lookupKey, adminKey: adminKey, intentKey: intentKey}
	token, err := signer.SignAccessToken(compositionActor, map[string]any{"sid": compositionSID, "role": "student"}, time.Minute)
	if err != nil {
		t.Fatal("source session token unavailable")
	}
	return MentorCompositionConfig{Enabled: true, RoleDecision: role, OwnerLookup: lookup, RBACReplyPublicPEM: admin.PublicPEM, MentorReplyPublicPEM: intent.PublicPEM},
		MentorCompositionDependencies{DB: gdb, Parser: signer, Requester: owners}, session, owners, token
}

func compositionHTTP(handler http.Handler, path, body, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://auth.example"+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestMentorCompositionDisabledIsInert(t *testing.T) {
	cfg, deps, session, owners, _ := compositionFixture(t)
	cfg.Enabled = false
	cfg.RoleDecision = MentorCompositionKeyPair{PrivatePEM: "invalid", PublicPEM: "invalid"}
	deps.Parser = (*compositionNilParser)(nil)
	handler, err := NewMentorComposition(cfg, deps)
	if handler != nil || err != nil || session.connects != 0 || session.queries != 0 || owners.adminCalls != 0 || owners.intentCalls != 0 {
		t.Fatal("disabled composition inspected authority or performed I/O")
	}
	handler, err = NewMentorComposition(MentorCompositionConfig{}, MentorCompositionDependencies{})
	if handler != nil || err != nil {
		t.Fatal("zero configuration did not stay disabled")
	}
}

func TestMentorCompositionRejectsIncompleteAndSharedAuthority(t *testing.T) {
	cfg, deps, session, owners, _ := compositionFixture(t)
	lookupKey, _ := compositionKey(t, 2)
	sharedModulus := &rsa.PublicKey{N: lookupKey.N, E: 17}
	for _, test := range []struct {
		name   string
		change func(*MentorCompositionConfig, *MentorCompositionDependencies)
	}{
		{"missing database", func(_ *MentorCompositionConfig, d *MentorCompositionDependencies) { d.DB = nil }},
		{"incomplete database", func(_ *MentorCompositionConfig, d *MentorCompositionDependencies) { d.DB = &gorm.DB{} }},
		{"typed nil database pool", func(_ *MentorCompositionConfig, d *MentorCompositionDependencies) {
			copyDB, copyConfig := *d.DB, *d.DB.Config
			copyStatement := gorm.Statement{DB: &copyDB}
			copyConfig.ConnPool, copyStatement.ConnPool = (*sql.DB)(nil), (*sql.DB)(nil)
			copyDB.Config, copyDB.Statement = &copyConfig, &copyStatement
			d.DB = &copyDB
		}},
		{"nil parser", func(_ *MentorCompositionConfig, d *MentorCompositionDependencies) { d.Parser = nil }},
		{"typed nil parser", func(_ *MentorCompositionConfig, d *MentorCompositionDependencies) {
			d.Parser = (*compositionNilParser)(nil)
		}},
		{"nil requester", func(_ *MentorCompositionConfig, d *MentorCompositionDependencies) { d.Requester = nil }},
		{"typed nil requester", func(_ *MentorCompositionConfig, d *MentorCompositionDependencies) {
			d.Requester = (*compositionRequester)(nil)
		}},
		{"missing role private key", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) { c.RoleDecision.PrivatePEM = "" }},
		{"missing lookup private key", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) { c.OwnerLookup.PrivatePEM = "" }},
		{"missing reply key", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) { c.MentorReplyPublicPEM = "" }},
		{"mismatched role pair", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) {
			c.RoleDecision.PrivatePEM = c.OwnerLookup.PrivatePEM
		}},
		{"mismatched lookup pair", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) {
			c.OwnerLookup.PrivatePEM = c.RoleDecision.PrivatePEM
		}},
		{"same lookup and role key", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) { c.OwnerLookup = c.RoleDecision }},
		{"same reply key", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) {
			c.MentorReplyPublicPEM = c.RBACReplyPublicPEM
		}},
		{"same role and reply key", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) {
			c.RBACReplyPublicPEM = c.RoleDecision.PublicPEM
		}},
		{"shared modulus with different exponent", func(c *MentorCompositionConfig, _ *MentorCompositionDependencies) {
			c.RBACReplyPublicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(sharedModulus)}))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			currentConfig, currentDeps := cfg, deps
			test.change(&currentConfig, &currentDeps)
			handler, err := NewMentorComposition(currentConfig, currentDeps)
			if handler != nil || err != ErrMentorCompositionUnavailable {
				t.Fatal("invalid enabled composition did not fail closed")
			}
			if session.connects != 0 || session.queries != 0 || owners.adminCalls != 0 || owners.intentCalls != 0 {
				t.Fatal("construction performed external work")
			}
		})
	}
}

func TestMentorCompositionUsesActualSessionOwnersAndIssuer(t *testing.T) {
	cfg, deps, session, owners, token := compositionFixture(t)
	handler, err := NewMentorComposition(cfg, deps)
	if err != nil || handler == nil || session.connects != 0 || session.queries != 0 || owners.adminCalls != 0 || owners.intentCalls != 0 {
		t.Fatal("valid composition unavailable or construction was not inert")
	}
	user := compositionHTTP(handler, internalhttp.MentorSessionVerifyPath, "{}", token)
	if user.Code != http.StatusOK || !strings.Contains(user.Body.String(), compositionActor) || session.queries != 1 || owners.adminCalls != 0 {
		t.Fatal("actual token and persisted-session path was not composed")
	}
	admin := compositionHTTP(handler, internalhttp.MentorAdminSessionVerifyPath, "{}", token)
	if admin.Code != http.StatusOK || session.queries != 3 || owners.adminCalls != 1 || owners.intentCalls != 0 {
		t.Fatal("actual signed Admin owner client or same-session recheck was not composed")
	}
	digest := sha256.Sum256([]byte("APPROVE|" + compositionActor + "|" + compositionApp + "|" + compositionRequest + "|1"))
	body, err := json.Marshal(map[string]any{"target_user_id": compositionTarget, "application_id": compositionApp,
		"application_revision": 2, "decision": "APPROVE", "request_id": compositionRequest, "decision_digest": hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal("source command unavailable")
	}
	issued := compositionHTTP(handler, internalhttp.MentorRoleDecisionPath, string(body), token)
	if issued.Code != http.StatusOK || session.queries != 5 || owners.adminCalls != 2 || owners.intentCalls != 1 {
		t.Fatal("actual committed-intent and role-issuance path was not composed")
	}
	var envelope map[string]string
	if json.Unmarshal(issued.Body.Bytes(), &envelope) != nil || len(envelope) != 1 || envelope["proof"] == "" {
		t.Fatal("missing exact issued-proof envelope")
	}
	roleKey, _ := compositionKey(t, 1)
	proof, err := jwt.Parse(envelope["proof"], func(*jwt.Token) (any, error) { return &roleKey.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("ms-go-auth"), jwt.WithAudience("ms-go-rbac-mentor-role"))
	if err != nil || !proof.Valid {
		t.Fatal("composed issuer did not use dedicated role key")
	}
	claims := proof.Claims.(jwt.MapClaims)
	if claims["sub"] != compositionActor || claims["target_user_id"] != compositionTarget ||
		claims["purpose"] != "AUTH_RBAC_MENTOR_ROLE_DECISION_V1" || claims["request_id"] != compositionRequest {
		t.Fatal("composed issuer changed command ownership")
	}
}

func TestMentorCompositionKeepsUnavailableAndAbsentSessionDistinct(t *testing.T) {
	cfg, deps, session, owners, token := compositionFixture(t)
	handler, err := NewMentorComposition(cfg, deps)
	if err != nil || handler == nil {
		t.Fatal("valid composition unavailable")
	}
	owners.err = errors.New("private dependency diagnostic")
	response := compositionHTTP(handler, internalhttp.MentorAdminSessionVerifyPath, "{}", token)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private") || owners.adminCalls != 1 {
		t.Fatal("composed owner outage became authorization or leaked diagnostics")
	}
	session.active = false
	response = compositionHTTP(handler, internalhttp.MentorAdminSessionVerifyPath, "{}", token)
	if response.Code != http.StatusUnauthorized || owners.adminCalls != 1 || owners.intentCalls != 0 {
		t.Fatal("absent live session reached owner confirmation")
	}
	session.err = errors.New("private database diagnostic")
	response = compositionHTTP(handler, internalhttp.MentorSessionVerifyPath, "{}", token)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private") {
		t.Fatal("actual persistence outage became false absence or leaked diagnostics")
	}
}
