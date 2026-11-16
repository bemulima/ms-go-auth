package natsadapter

import (
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
	"sync"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	nats "github.com/nats-io/nats.go"
)

const (
	lookupTestActor   = "11111111-1111-4111-8111-111111111111"
	lookupTestTarget  = "22222222-2222-4222-8222-222222222222"
	lookupTestApp     = "33333333-3333-4333-8333-333333333333"
	lookupTestCommand = "44444444-4444-4444-8444-444444444444"
)

var lookupTestKeyCache struct {
	sync.Once
	keys [4]*rsa.PrivateKey
	err  error
}

func lookupTestKeys(t *testing.T) [4]*rsa.PrivateKey {
	t.Helper()
	lookupTestKeyCache.Do(func() {
		for i := range lookupTestKeyCache.keys {
			lookupTestKeyCache.keys[i], lookupTestKeyCache.err = rsa.GenerateKey(rand.Reader, 2048)
			if lookupTestKeyCache.err != nil {
				return
			}
		}
	})
	if lookupTestKeyCache.err != nil {
		t.Fatal("ephemeral lookup keys could not be generated")
	}
	return lookupTestKeyCache.keys
}

func lookupTestPrivate(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func lookupTestPublic(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
}

func lookupTestBinding(decision string, revision int64) domain.MentorRoleDecisionBinding {
	digest := sha256.Sum256([]byte(strings.Join([]string{decision, lookupTestActor, lookupTestApp, lookupTestCommand, strconv.FormatInt(revision-1, 10)}, "|")))
	return domain.MentorRoleDecisionBinding{
		AdminActorID: lookupTestActor,
		MentorRoleDecisionRequest: domain.MentorRoleDecisionRequest{
			TargetUserID: lookupTestTarget, ApplicationID: lookupTestApp, ApplicationRevision: revision,
			Decision: decision, RequestID: lookupTestCommand, DecisionDigest: hex.EncodeToString(digest[:]),
		},
	}
}

type lookupTestRequest struct {
	proof   string
	claims  map[string]json.RawMessage
	subject string
}

func (r lookupTestRequest) text(field string) string {
	var value string
	_ = json.Unmarshal(r.claims[field], &value)
	return value
}

func (r lookupTestRequest) integer(field string) int64 {
	var value int64
	_ = json.Unmarshal(r.claims[field], &value)
	return value
}

type lookupTestRequester struct {
	t     *testing.T
	keys  [4]*rsa.PrivateKey
	now   time.Time
	calls int
	seen  []lookupTestRequest
	reply func(context.Context, lookupTestRequest) ([]byte, error)
}

func (f *lookupTestRequester) RequestWithContext(ctx context.Context, subject string, body []byte) (*nats.Msg, error) {
	f.calls++
	request := f.checkRequest(subject, body)
	f.seen = append(f.seen, request)
	if f.reply != nil {
		data, err := f.reply(ctx, request)
		if err != nil {
			return nil, err
		}
		return &nats.Msg{Data: data}, nil
	}
	return &nats.Msg{Data: f.envelope(request, f.replyClaims(request, "ALLOW"), -1)}, nil
}

func (f *lookupTestRequester) checkRequest(subject string, body []byte) lookupTestRequest {
	f.t.Helper()
	var envelope map[string]json.RawMessage
	if len(body) > 16384 || json.Unmarshal(body, &envelope) != nil || len(envelope) != 1 {
		f.t.Fatal("request envelope must contain only a signed proof")
	}
	var proof string
	if json.Unmarshal(envelope["proof"], &proof) != nil || len(proof) == 0 || len(proof) > 8192 {
		f.t.Fatal("invalid request proof envelope")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		f.t.Fatal("request proof is not compact JWT")
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		var err error
		decoded[i], err = base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded[i]) != part {
			f.t.Fatal("request encoding is not canonical")
		}
	}
	var header map[string]any
	if json.Unmarshal(decoded[0], &header) != nil || !reflect.DeepEqual(header, map[string]any{"alg": "RS256", "typ": "JWT"}) {
		f.t.Fatal("unexpected request proof header")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.keys[0].PublicKey, crypto.SHA256, digest[:], decoded[2]) != nil {
		f.t.Fatal("request proof did not verify with the dedicated lookup key")
	}
	request := lookupTestRequest{proof: proof, subject: subject}
	if json.Unmarshal(decoded[1], &request.claims) != nil {
		f.t.Fatal("invalid request claims")
	}
	wantCount, aud, typ, purpose := 9, "ms-go-rbac-mentor-canonical-admin", "mentor_canonical_admin_check", "AUTH_RBAC_MENTOR_CANONICAL_ADMIN_LOOKUP_V1"
	if subject == "mentor.confirmCommittedRoleIntent.v1" {
		wantCount, aud, typ, purpose = 15, "ms-go-mentor-committed-role-intent", "mentor_committed_role_intent_check", "AUTH_MENTOR_COMMITTED_ROLE_INTENT_V1"
	} else if subject != "rbac.checkMentorCanonicalAdmin.v1" {
		f.t.Fatal("request used a noncanonical NATS subject")
	}
	if len(request.claims) != wantCount || request.text("iss") != "ms-go-auth" || request.text("aud") != aud || request.text("typ") != typ || request.text("purpose") != purpose || request.text("sub") != lookupTestActor || request.text("subject") != subject || !validNonZeroCanonicalReviewerUUID(request.text("jti")) {
		f.t.Fatal("request claims or fixed operation binding differ from contract")
	}
	for _, field := range []string{"iat", "exp"} {
		if string(request.claims[field]) != strconv.FormatInt(request.integer(field), 10) {
			f.t.Fatal("request timestamp must be an exact JSON integer")
		}
	}
	if request.integer("iat") != f.now.Unix() || request.integer("exp")-request.integer("iat") != 30 {
		f.t.Fatal("request lifetime must be exactly 30 seconds")
	}
	if wantCount == 15 {
		binding := lookupTestBinding(request.text("decision"), request.integer("application_revision"))
		if request.text("target_user_id") != binding.TargetUserID || request.text("application_id") != binding.ApplicationID || request.text("request_id") != binding.RequestID || request.text("decision_digest") != binding.DecisionDigest {
			f.t.Fatal("request changed the committed intent binding")
		}
	}
	return request
}

func (f *lookupTestRequester) replyClaims(request lookupTestRequest, result string) map[string]any {
	digest := sha256.Sum256([]byte(request.proof))
	expires := f.now.Unix() + 15
	if expires > request.integer("exp") {
		expires = request.integer("exp")
	}
	claims := map[string]any{
		"iss": "ms-go-rbac", "aud": "ms-go-auth-mentor-canonical-admin-decision", "typ": "mentor_canonical_admin_decision", "purpose": "RBAC_AUTH_MENTOR_CANONICAL_ADMIN_DECISION_V1",
		"sub": request.text("sub"), "subject": request.subject, "jti": fmt.Sprintf("66666666-6666-4666-8666-%012d", f.calls),
		"iat": f.now.Unix(), "exp": expires, "decision": result, "request_jti": request.text("jti"), "request_digest": hex.EncodeToString(digest[:]),
	}
	if request.subject == MentorCommittedIntentLookupSubject {
		claims["iss"], claims["aud"], claims["typ"], claims["purpose"] = "ms-go-mentor", "ms-go-auth-mentor-committed-role-intent-decision", "mentor_committed_role_intent_decision", "MENTOR_AUTH_COMMITTED_ROLE_INTENT_DECISION_V1"
		claims["result"] = result
		claims["state"] = "UNCONFIRMED"
		if result == "ALLOW" {
			claims["state"] = "APPROVAL_PENDING_GRANT"
			if request.text("decision") == "SUSPEND" {
				claims["state"] = "SUSPENDED"
			}
		}
		for _, field := range []string{"target_user_id", "application_id", "decision", "request_id", "decision_digest"} {
			claims[field] = request.text(field)
		}
		claims["application_revision"] = request.integer("application_revision")
	}
	return claims
}

func lookupTestSign(t *testing.T, key *rsa.PrivateKey, header, claims []byte) string {
	t.Helper()
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("ephemeral reply signing failed")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *lookupTestRequester) envelope(request lookupTestRequest, claims map[string]any, keyIndex int) []byte {
	if keyIndex < 0 {
		keyIndex = 1
		if request.subject == MentorCommittedIntentLookupSubject {
			keyIndex = 2
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatal("test reply encoding failed")
	}
	token := lookupTestSign(f.t, f.keys[keyIndex], []byte(`{"alg":"RS256","typ":"JWT"}`), payload)
	return []byte(`{"decision_jwt":"` + token + `"}`)
}

func lookupClientFixture(t *testing.T) (*MentorOwnerConfirmationClient, *lookupTestRequester) {
	t.Helper()
	f := &lookupTestRequester{t: t, keys: lookupTestKeys(t), now: time.Unix(1_800_000_000, 0)}
	c, err := NewMentorOwnerConfirmationClient(f, lookupTestPrivate(f.keys[0]), lookupTestPublic(f.keys[0]), lookupTestPublic(f.keys[1]), lookupTestPublic(f.keys[2]))
	if err != nil || c == nil {
		t.Fatal("valid isolated keys and requester must create client")
	}
	c.now = func() time.Time { return f.now }
	return c, f
}

func lookupCall(t *testing.T, c *MentorOwnerConfirmationClient, kind string, ctx context.Context) (bool, error) {
	t.Helper()
	if kind == "admin" {
		result, err := c.ConfirmCanonicalAdmin(ctx, lookupTestActor)
		if err != nil {
			if result != nil {
				t.Fatal("unavailable reply must not expose a typed confirmation")
			}
			return false, err
		}
		if result == nil || result.ActorID != lookupTestActor {
			t.Fatal("confirmation must bind exactly the requested actor")
		}
		return result.UniqueCanonicalDefaultAdmin, nil
	}
	binding := lookupTestBinding("APPROVE", 2)
	result, err := c.ConfirmCommittedMentorIntent(ctx, binding)
	if err != nil {
		if result != nil {
			t.Fatal("unavailable reply must not expose a typed confirmation")
		}
		return false, err
	}
	if result == nil || result.Binding != binding || result.Committed != result.Current {
		t.Fatal("intent confirmation lost its exact binding")
	}
	if result.Current && result.State != "APPROVAL_PENDING_GRANT" || !result.Current && result.State != "UNCONFIRMED" {
		t.Fatal("confirmation disclosed incompatible intent state")
	}
	return result.Current, nil
}

func TestMentorOwnerClientSignsExactRequestsAndAcceptsBoundOwnerAllowDeny(t *testing.T) {
	for _, kind := range []string{"admin", "intent"} {
		for _, decision := range []string{"ALLOW", "DENY"} {
			t.Run(kind+decision, func(t *testing.T) {
				c, f := lookupClientFixture(t)
				f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
					return f.envelope(r, f.replyClaims(r, decision), -1), nil
				}
				allowed, err := lookupCall(t, c, kind, context.Background())
				if err != nil || allowed != (decision == "ALLOW") || f.calls != 1 {
					t.Fatal("valid signed owner decision was not accepted exactly")
				}
			})
		}
	}
	for _, revision := range []int64{3, 4} {
		t.Run(fmt.Sprintf("suspend%d", revision), func(t *testing.T) {
			c, f := lookupClientFixture(t)
			binding := lookupTestBinding("SUSPEND", revision)
			confirmation, err := c.ConfirmCommittedMentorIntent(context.Background(), binding)
			if err != nil || confirmation == nil || !confirmation.Committed || !confirmation.Current || confirmation.State != "SUSPENDED" || confirmation.Binding != binding || f.calls != 1 {
				t.Fatal("current suspended intent must confirm exact revision")
			}
		})
	}
}

func TestMentorOwnerClientGeneratesFreshNonceAndRejectsPreviousReply(t *testing.T) {
	for _, kind := range []string{"admin", "intent"} {
		t.Run(kind, func(t *testing.T) {
			c, f := lookupClientFixture(t)
			var previous []byte
			f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
				if previous == nil {
					previous = f.envelope(r, f.replyClaims(r, "ALLOW"), -1)
				}
				return previous, nil
			}
			if allowed, err := lookupCall(t, c, kind, context.Background()); err != nil || !allowed {
				t.Fatal("first bound response should be accepted")
			}
			if allowed, err := lookupCall(t, c, kind, context.Background()); allowed || !errors.Is(err, ErrMentorOwnerConfirmationUnavailable) {
				t.Fatal("prior request response must not authorize fresh lookup")
			}
			if f.calls != 2 || f.seen[0].text("jti") == f.seen[1].text("jti") || f.seen[0].proof == f.seen[1].proof {
				t.Fatal("lookup reused nonce or proof")
			}
			f.reply = nil
			if allowed, err := lookupCall(t, c, kind, context.Background()); err != nil || !allowed || f.calls != 3 {
				t.Fatal("denied old response must not poison a future valid lookup")
			}
		})
	}
}

func TestMentorOwnerClientRejectsReplyBindingAndLifetimeMismatches(t *testing.T) {
	mutators := map[string]func(map[string]any, lookupTestRequest){
		"issuer":         func(c map[string]any, _ lookupTestRequest) { c["iss"] = "foreign" },
		"audience":       func(c map[string]any, _ lookupTestRequest) { c["aud"] = "other" },
		"type":           func(c map[string]any, _ lookupTestRequest) { c["typ"] = "mentor_role_decision" },
		"purpose":        func(c map[string]any, _ lookupTestRequest) { c["purpose"] = "AUTH_RBAC_MENTOR_ROLE_DECISION_V1" },
		"actor":          func(c map[string]any, _ lookupTestRequest) { c["sub"] = lookupTestTarget },
		"nats subject":   func(c map[string]any, _ lookupTestRequest) { c["subject"] = "rbac.checkRole" },
		"request nonce":  func(c map[string]any, _ lookupTestRequest) { c["request_jti"] = lookupTestTarget },
		"request digest": func(c map[string]any, _ lookupTestRequest) { c["request_digest"] = strings.Repeat("a", 64) },
		"uppercase request digest": func(c map[string]any, _ lookupTestRequest) {
			c["request_digest"] = strings.ToUpper(c["request_digest"].(string))
		},
		"zero response nonce":       func(c map[string]any, _ lookupTestRequest) { c["jti"] = "00000000-0000-0000-0000-000000000000" },
		"request nonce as response": func(c map[string]any, r lookupTestRequest) { c["jti"] = r.text("jti") },
		"unknown field":             func(c map[string]any, _ lookupTestRequest) { c["role"] = "admin" },
		"null":                      func(c map[string]any, _ lookupTestRequest) { c["sub"] = nil },
		"missing":                   func(c map[string]any, _ lookupTestRequest) { delete(c, "purpose") },
		"case alias":                func(c map[string]any, _ lookupTestRequest) { c["ISS"] = c["iss"]; delete(c, "iss") },
		"nonstring audience":        func(c map[string]any, _ lookupTestRequest) { c["aud"] = []string{c["aud"].(string)} },
		"zero iat":                  func(c map[string]any, _ lookupTestRequest) { c["iat"] = int64(0) },
		"negative iat":              func(c map[string]any, _ lookupTestRequest) { c["iat"] = int64(-1) },
		"expired equality":          func(c map[string]any, r lookupTestRequest) { c["exp"] = r.integer("iat") },
		"no positive lifetime":      func(c map[string]any, _ lookupTestRequest) { c["iat"] = c["exp"] },
		"ttl16":                     func(c map[string]any, r lookupTestRequest) { c["exp"] = r.integer("iat") + 16 },
		"future6":                   func(c map[string]any, r lookupTestRequest) { c["iat"] = r.integer("iat") + 6 },
		"unsafe integer":            func(c map[string]any, _ lookupTestRequest) { c["exp"] = int64(9007199254740992) },
		"max int overflow": func(c map[string]any, _ lookupTestRequest) {
			c["iat"] = int64(9223372036854775806)
			c["exp"] = int64(9223372036854775807)
		},
	}
	for _, kind := range []string{"admin", "intent"} {
		for name, mutate := range mutators {
			t.Run(kind+"/"+name, func(t *testing.T) {
				c, f := lookupClientFixture(t)
				f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
					claims := f.replyClaims(r, "ALLOW")
					mutate(claims, r)
					return f.envelope(r, claims, -1), nil
				}
				if allowed, err := lookupCall(t, c, kind, context.Background()); allowed || !errors.Is(err, ErrMentorOwnerConfirmationUnavailable) {
					t.Fatal("untrusted/mismatched owner reply was accepted")
				}
			})
		}
	}
}

func TestMentorOwnerClientRejectsWrongOperationResultOrIntentFields(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"target":              func(c map[string]any) { c["target_user_id"] = lookupTestActor },
		"application":         func(c map[string]any) { c["application_id"] = lookupTestTarget },
		"revision":            func(c map[string]any) { c["application_revision"] = 3 },
		"decision":            func(c map[string]any) { c["decision"] = "SUSPEND" },
		"command":             func(c map[string]any) { c["request_id"] = lookupTestTarget },
		"digest":              func(c map[string]any) { c["decision_digest"] = strings.Repeat("a", 64) },
		"unknown result":      func(c map[string]any) { c["result"] = "PERMIT" },
		"wrong allowed state": func(c map[string]any) { c["state"] = "APPROVED" },
		"unconfirmed allow":   func(c map[string]any) { c["state"] = "UNCONFIRMED" },
		"deny actual state":   func(c map[string]any) { c["result"] = "DENY" },
		"role as result":      func(c map[string]any) { delete(c, "result"); c["role"] = "mentor" },
	} {
		t.Run(name, func(t *testing.T) {
			c, f := lookupClientFixture(t)
			f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
				claims := f.replyClaims(r, "ALLOW")
				mutate(claims)
				return f.envelope(r, claims, -1), nil
			}
			if allowed, err := lookupCall(t, c, "intent", context.Background()); allowed || err == nil {
				t.Fatal("foreign intent or invalid semantic result was accepted")
			}
		})
	}
	c, f := lookupClientFixture(t)
	f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
		claims := f.replyClaims(r, "ALLOW")
		claims["decision"] = "allow"
		return f.envelope(r, claims, -1), nil
	}
	if allowed, err := lookupCall(t, c, "admin", context.Background()); allowed || err == nil {
		t.Fatal("Admin decision must be exact ALLOW or DENY")
	}
}

func TestMentorOwnerClientRejectsBadKeysSignaturesAndEncoding(t *testing.T) {
	for _, kind := range []string{"admin", "intent"} {
		for _, mode := range []string{"foreign key", "other owner key", "lookup key", "signature flip", "padded encoding", "noncanonical bits", "extra segment", "empty segment", "none", "HS256", "kid", "duplicate header", "unknown header", "null header"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				c, f := lookupClientFixture(t)
				f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
					keyIndex := 1
					if kind == "intent" {
						keyIndex = 2
					}
					switch mode {
					case "foreign key":
						keyIndex = 3
					case "other owner key":
						keyIndex = 3 - keyIndex
					case "lookup key":
						keyIndex = 0
					}
					claims, _ := json.Marshal(f.replyClaims(r, "ALLOW"))
					header := `{"alg":"RS256","typ":"JWT"}`
					switch mode {
					case "none":
						header = `{"alg":"none","typ":"JWT"}`
					case "HS256":
						header = `{"alg":"HS256","typ":"JWT"}`
					case "kid":
						header = `{"alg":"RS256","typ":"JWT","kid":"foreign"}`
					case "duplicate header":
						header = `{"alg":"RS256","typ":"JWT","alg":"RS256"}`
					case "unknown header":
						header = `{"alg":"RS256","typ":"JWT","jku":"https://invalid.test"}`
					case "null header":
						header = `{"alg":"RS256","typ":null}`
					}
					token := lookupTestSign(t, f.keys[keyIndex], []byte(header), claims)
					parts := strings.Split(token, ".")
					switch mode {
					case "signature flip":
						decoded, _ := base64.RawURLEncoding.DecodeString(parts[2])
						decoded[0] ^= 1
						parts[2] = base64.RawURLEncoding.EncodeToString(decoded)
					case "padded encoding":
						parts[2] += "=="
					case "noncanonical bits":
						const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
						last := strings.IndexByte(alphabet, parts[2][len(parts[2])-1])
						parts[2] = parts[2][:len(parts[2])-1] + string(alphabet[last|1])
					case "extra segment":
						parts = append(parts, "extra")
					case "empty segment":
						parts[1] = ""
					}
					return []byte(`{"decision_jwt":"` + strings.Join(parts, ".") + `"}`), nil
				}
				if allowed, err := lookupCall(t, c, kind, context.Background()); allowed || !errors.Is(err, ErrMentorOwnerConfirmationUnavailable) {
					t.Fatal("bad signature/header/encoding was accepted")
				}
			})
		}
	}
}

func TestMentorOwnerClientRejectsInexactJSONClaimsAndEnvelopes(t *testing.T) {
	for _, kind := range []string{"admin", "intent"} {
		for _, mode := range []string{"duplicate claim", "escaped duplicate claim", "trailing claims", "fraction iat", "exponent iat", "string iat", "duplicate envelope", "escaped duplicate envelope", "unknown envelope", "null envelope", "case envelope", "trailing envelope", "unsigned pass", "empty reply", "oversize envelope", "oversize token"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				c, f := lookupClientFixture(t)
				f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
					payload, _ := json.Marshal(f.replyClaims(r, "ALLOW"))
					raw := string(payload)
					switch mode {
					case "duplicate claim":
						raw = raw[:len(raw)-1] + `,"sub":"` + lookupTestActor + `"}`
					case "escaped duplicate claim":
						raw = raw[:len(raw)-1] + `,"\u0073ub":"` + lookupTestActor + `"}`
					case "trailing claims":
						raw += " {}"
					case "fraction iat":
						raw = strings.Replace(raw, `"iat":1800000000`, `"iat":1800000000.0`, 1)
					case "exponent iat":
						raw = strings.Replace(raw, `"iat":1800000000`, `"iat":18e8`, 1)
					case "string iat":
						raw = strings.Replace(raw, `"iat":1800000000`, `"iat":"1800000000"`, 1)
					}
					keyIndex := 1
					if kind == "intent" {
						keyIndex = 2
					}
					token := lookupTestSign(t, f.keys[keyIndex], []byte(`{"alg":"RS256","typ":"JWT"}`), []byte(raw))
					body := `{"decision_jwt":"` + token + `"}`
					switch mode {
					case "duplicate envelope":
						body = body[:len(body)-1] + `,"decision_jwt":"` + token + `"}`
					case "escaped duplicate envelope":
						body = body[:len(body)-1] + `,"decision_\u006awt":"` + token + `"}`
					case "unknown envelope":
						body = body[:len(body)-1] + `,"ok":true}`
					case "null envelope":
						body = `{"decision_jwt":null}`
					case "case envelope":
						body = strings.Replace(body, "decision_jwt", "Decision_jwt", 1)
					case "trailing envelope":
						body += " {}"
					case "unsigned pass":
						body = `{"ok":true}`
					case "empty reply":
						body = ""
					case "oversize envelope":
						body = strings.Repeat(" ", 16385) + body
					case "oversize token":
						body = `{"decision_jwt":"` + strings.Repeat("a", 8193) + `"}`
					}
					return []byte(body), nil
				}
				if allowed, err := lookupCall(t, c, kind, context.Background()); allowed || !errors.Is(err, ErrMentorOwnerConfirmationUnavailable) {
					t.Fatal("inexact JSON or limit violation was accepted")
				}
			})
		}
	}
}

func TestMentorOwnerClientRejectsInvalidInputWithoutNetwork(t *testing.T) {
	for _, actor := range []string{"", "not-uuid", "00000000-0000-0000-0000-000000000000", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", lookupTestActor + " "} {
		c, f := lookupClientFixture(t)
		if confirmation, err := c.ConfirmCanonicalAdmin(context.Background(), actor); confirmation != nil || err == nil || f.calls != 0 {
			t.Fatal("invalid actor reached network")
		}
	}
	for name, mutate := range map[string]func(*domain.MentorRoleDecisionBinding){
		"actor":            func(b *domain.MentorRoleDecisionBinding) { b.AdminActorID = "not-uuid" },
		"target":           func(b *domain.MentorRoleDecisionBinding) { b.TargetUserID = "" },
		"application":      func(b *domain.MentorRoleDecisionBinding) { b.ApplicationID = "00000000-0000-0000-0000-000000000000" },
		"request":          func(b *domain.MentorRoleDecisionBinding) { b.RequestID = strings.ReplaceAll(b.RequestID, "-", "") },
		"approve revision": func(b *domain.MentorRoleDecisionBinding) { b.ApplicationRevision = 3 },
		"suspend revision": func(b *domain.MentorRoleDecisionBinding) { b.Decision = "SUSPEND" },
		"decision":         func(b *domain.MentorRoleDecisionBinding) { b.Decision = "REJECT" },
		"digest":           func(b *domain.MentorRoleDecisionBinding) { b.DecisionDigest = strings.Repeat("a", 64) },
		"uppercase digest": func(b *domain.MentorRoleDecisionBinding) { b.DecisionDigest = strings.ToUpper(b.DecisionDigest) },
	} {
		t.Run(name, func(t *testing.T) {
			c, f := lookupClientFixture(t)
			binding := lookupTestBinding("APPROVE", 2)
			mutate(&binding)
			if confirmation, err := c.ConfirmCommittedMentorIntent(context.Background(), binding); confirmation != nil || err == nil || f.calls != 0 {
				t.Fatal("invalid bound intent reached network")
			}
		})
	}
}

func TestMentorOwnerClientClockBoundariesAndExpiryCap(t *testing.T) {
	for _, kind := range []string{"admin", "intent"} {
		for _, seconds := range []int64{-1, 0, 9007199254740991 - 29, 9007199254740991} {
			c, f := lookupClientFixture(t)
			f.now = time.Unix(seconds, 0)
			if allowed, err := lookupCall(t, c, kind, context.Background()); allowed || err == nil || f.calls != 0 {
				t.Fatal("invalid issuance time reached network")
			}
		}
		for _, mode := range []string{"capped allow", "beyond request expiry", "expired request", "backward clock", "future five"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				c, f := lookupClientFixture(t)
				f.reply = func(_ context.Context, r lookupTestRequest) ([]byte, error) {
					switch mode {
					case "capped allow", "beyond request expiry":
						f.now = f.now.Add(20 * time.Second)
					case "expired request":
						f.now = f.now.Add(30 * time.Second)
					case "backward clock":
						f.now = f.now.Add(-6 * time.Second)
					}
					claims := f.replyClaims(r, "ALLOW")
					if mode == "beyond request expiry" {
						claims["exp"] = r.integer("exp") + 1
					}
					if mode == "future five" {
						claims["iat"] = r.integer("iat") + 5
					}
					return f.envelope(r, claims, -1), nil
				}
				allowed, err := lookupCall(t, c, kind, context.Background())
				want := mode == "capped allow" || mode == "future five"
				if allowed != want || (err == nil) != want {
					t.Fatal("request expiry/skew or response cap not enforced")
				}
			})
		}
	}
}

func TestMentorOwnerClientDeadlinesCancellationAndErrors(t *testing.T) {
	for _, kind := range []string{"admin", "intent"} {
		for _, mode := range []string{"three second cap", "shorter parent", "already canceled", "cancel after network", "deadline after network", "dependency failure"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				c, f := lookupClientFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "shorter parent" || mode == "deadline after network" {
					var shortCancel context.CancelFunc
					parentTimeout := time.Second
					if mode == "deadline after network" {
						parentTimeout = 20 * time.Millisecond
					}
					ctx, shortCancel = context.WithTimeout(ctx, parentTimeout)
					defer shortCancel()
				}
				if mode == "already canceled" {
					cancel()
				}
				f.reply = func(callCtx context.Context, r lookupTestRequest) ([]byte, error) {
					deadline, ok := callCtx.Deadline()
					if !ok || time.Until(deadline) > 3*time.Second {
						t.Fatal("lookup must have a three-second deadline")
					}
					if mode == "shorter parent" || mode == "deadline after network" {
						parentDeadline, _ := ctx.Deadline()
						if !deadline.Equal(parentDeadline) {
							t.Fatal("shorter parent deadline was not preserved")
						}
					}
					if mode == "cancel after network" {
						cancel()
					}
					if mode == "deadline after network" {
						<-callCtx.Done()
					}
					if mode == "dependency failure" {
						return nil, errors.New("private diagnostic must never escape")
					}
					return f.envelope(r, f.replyClaims(r, "ALLOW"), -1), nil
				}
				allowed, err := lookupCall(t, c, kind, ctx)
				want := mode == "three second cap" || mode == "shorter parent"
				if want {
					if !allowed || err != nil {
						t.Fatal("valid bounded lookup unexpectedly denied")
					}
				} else if allowed || !errors.Is(err, ErrMentorOwnerConfirmationUnavailable) || err.Error() != ErrMentorOwnerConfirmationUnavailable.Error() {
					t.Fatal("cancelled/failed lookup must return generic unavailable")
				}
				if mode == "already canceled" && f.calls != 0 {
					t.Fatal("canceled call reached network")
				}
				if f.calls > 1 {
					t.Fatal("lookup automatically retried")
				}
			})
		}
	}
}

func TestMentorOwnerClientConfigurationFailsClosed(t *testing.T) {
	keys := lookupTestKeys(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("test-only weak key generation failed")
	}
	for _, mode := range []string{"nil requester", "typed nil requester", "no private", "no lookup public", "no rbac public", "no mentor public", "mismatched pair", "weak pair", "weak rbac", "weak mentor", "invalid private", "invalid public", "trailing private PEM", "trailing public PEM", "shared owner reply key", "lookup key as rbac reply", "lookup key as mentor reply"} {
		t.Run(mode, func(t *testing.T) {
			f := &lookupTestRequester{t: t, keys: keys}
			var requester MentorOwnerNATSRequester = f
			private, pub, rbac, mentor := lookupTestPrivate(keys[0]), lookupTestPublic(keys[0]), lookupTestPublic(keys[1]), lookupTestPublic(keys[2])
			switch mode {
			case "nil requester":
				requester = nil
			case "typed nil requester":
				requester = (*lookupTestRequester)(nil)
			case "no private":
				private = ""
			case "no lookup public":
				pub = ""
			case "no rbac public":
				rbac = ""
			case "no mentor public":
				mentor = ""
			case "mismatched pair":
				pub = lookupTestPublic(keys[3])
			case "weak pair":
				private = lookupTestPrivate(weak)
				pub = lookupTestPublic(weak)
			case "weak rbac":
				rbac = lookupTestPublic(weak)
			case "weak mentor":
				mentor = lookupTestPublic(weak)
			case "invalid private":
				private = "invalid"
			case "invalid public":
				pub = "invalid"
			case "trailing private PEM":
				private += private
			case "trailing public PEM":
				pub += pub
			case "shared owner reply key":
				mentor = rbac
			case "lookup key as rbac reply":
				rbac = pub
			case "lookup key as mentor reply":
				mentor = pub
			}
			if client, err := NewMentorOwnerConfirmationClient(requester, private, pub, rbac, mentor); client != nil || !errors.Is(err, ErrMentorOwnerConfirmationUnavailable) {
				t.Fatal("invalid/absent/dedication-violating key or transport configuration must fail closed")
			}
		})
	}
	for _, client := range []*MentorOwnerConfirmationClient{nil, {}} {
		if result, err := client.ConfirmCanonicalAdmin(context.Background(), lookupTestActor); result != nil || err == nil {
			t.Fatal("nil/zero client must not confirm Admin")
		}
		if result, err := client.ConfirmCommittedMentorIntent(context.Background(), lookupTestBinding("APPROVE", 2)); result != nil || err == nil {
			t.Fatal("nil/zero client must not confirm intent")
		}
	}
}
