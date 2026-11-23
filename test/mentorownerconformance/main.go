//go:build mentorconformance

// Offline conformance driver. Stdio carries private test protocol frames; only
// the parent runner's final sanitized summary is a user-visible diagnostic.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/example/auth-service/internal/domain"
	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	"github.com/example/auth-service/internal/usecase"
	nats "github.com/nats-io/nats.go"
)

const (
	adminID       = "11111111-1111-4111-8111-111111111111"
	targetID      = "22222222-2222-4222-8222-222222222222"
	applicationID = "33333333-3333-4333-8333-333333333333"
	sessionID     = "44444444-4444-4444-8444-444444444444"
	approveID     = "55555555-5555-4555-8555-555555555555"
	suspendID     = "66666666-6666-4666-8666-666666666666"
	suspendFullID = "77777777-7777-4777-8777-777777777777"
	otherID       = "88888888-8888-4888-8888-888888888888"
)

type fixtureConfig struct {
	LookupPrivate string `json:"lookup_private_key"`
	LookupPublic  string `json:"lookup_public_key"`
	RBACPublic    string `json:"rbac_public_key"`
	MentorPublic  string `json:"mentor_public_key"`
}

type pipeTransport struct {
	scanner *bufio.Scanner
	encoder *json.Encoder
	mode    string
	calls   int
}

func (p *pipeTransport) RequestWithContext(ctx context.Context, subject string, data []byte) (*nats.Msg, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	p.calls++
	if err := p.encoder.Encode(struct {
		Kind    string          `json:"kind"`
		Mode    string          `json:"mode"`
		Subject string          `json:"subject"`
		Body    json.RawMessage `json:"body"`
	}{"rpc", p.mode, subject, data}); err != nil {
		return nil, errors.New("offline request pipe unavailable")
	}
	if !p.scanner.Scan() {
		return nil, errors.New("offline reply pipe unavailable")
	}
	var reply struct {
		Body        json.RawMessage `json:"body"`
		Unavailable bool            `json:"unavailable"`
	}
	if json.Unmarshal(p.scanner.Bytes(), &reply) != nil || reply.Unavailable {
		return nil, errors.New("offline owner unavailable")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &nats.Msg{Data: reply.Body}, nil
}

type sessionDouble struct{}

func (sessionDouble) VerifyToken(_ context.Context, _, token string) (*usecase.VerificationResult, error) {
	if token != "offline-current-session" {
		return nil, errors.New("fixture session denied")
	}
	return &usecase.VerificationResult{UserID: adminID, Claims: map[string]any{"sid": sessionID}}, nil
}

func binding(decision string, revision int64, requestID string) domain.MentorRoleDecisionBinding {
	digest := sha256.Sum256([]byte(decision + "|" + adminID + "|" + applicationID + "|" + requestID + "|" + strconv.FormatInt(revision-1, 10)))
	return domain.MentorRoleDecisionBinding{AdminActorID: adminID, MentorRoleDecisionRequest: domain.MentorRoleDecisionRequest{
		TargetUserID: targetID, ApplicationID: applicationID, ApplicationRevision: revision,
		Decision: decision, RequestID: requestID, DecisionDigest: hex.EncodeToString(digest[:]),
	}}
}

func exercise() error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		return errors.New("missing fixture configuration")
	}
	var config fixtureConfig
	if json.Unmarshal(scanner.Bytes(), &config) != nil {
		return errors.New("invalid fixture configuration")
	}
	pipe := &pipeTransport{scanner: scanner, encoder: json.NewEncoder(os.Stdout)}
	client, err := natsadapter.NewMentorOwnerConfirmationClient(pipe, config.LookupPrivate, config.LookupPublic, config.RBACPublic, config.MentorPublic)
	if err != nil {
		return errors.New("actual Auth owner client construction failed")
	}
	ctx := context.Background()
	checks := 0
	for _, test := range []struct {
		mode, actor        string
		allow, unavailable bool
	}{
		{"normal", adminID, true, false},
		{"normal", otherID, false, false},
		{"dependency", adminID, false, true},
		{"replay", adminID, false, true},
		{"unsigned", adminID, false, true},
		{"tamper", adminID, false, true},
		{"wrong_owner_key", adminID, false, true},
	} {
		pipe.mode = test.mode
		result, lookupErr := client.ConfirmCanonicalAdmin(ctx, test.actor)
		if test.unavailable {
			if lookupErr == nil || result != nil {
				return fmt.Errorf("untrusted Admin response admitted: %s", test.mode)
			}
		} else if lookupErr != nil || result == nil || result.ActorID != test.actor || result.UniqueCanonicalDefaultAdmin != test.allow {
			return fmt.Errorf("canonical Admin owner result mismatch: %s", test.mode)
		}
		checks++
	}
	approve := binding("APPROVE", 2, approveID)
	foreign := approve
	foreign.TargetUserID = otherID
	for _, test := range []struct {
		mode               string
		binding            domain.MentorRoleDecisionBinding
		allow, unavailable bool
		state              string
	}{
		{"normal", approve, true, false, "APPROVAL_PENDING_GRANT"},
		{"normal", foreign, false, false, ""},
		{"suspended", approve, false, false, ""},
		{"dependency", approve, false, true, ""},
		{"replay", approve, false, true, ""},
		{"suspended", binding("SUSPEND", 3, suspendID), true, false, "SUSPENDED"},
		{"suspended_approved", binding("SUSPEND", 4, suspendFullID), true, false, "SUSPENDED"},
	} {
		pipe.mode = test.mode
		result, lookupErr := client.ConfirmCommittedMentorIntent(ctx, test.binding)
		if test.unavailable {
			if lookupErr == nil || result != nil {
				return fmt.Errorf("untrusted Mentor response admitted: %s", test.mode)
			}
		} else if lookupErr != nil || result == nil || result.Binding != test.binding || result.Committed != test.allow || result.Current != test.allow || (test.allow && result.State != test.state) {
			return fmt.Errorf("committed Mentor owner result mismatch: %s", test.mode)
		}
		checks++
	}
	// Compose the actual final issuer with both actual authenticated adapters.
	// Only the current-session persistence/transport remains a test double here.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.New("final assertion fixture key generation failed")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return errors.New("final assertion public key encoding failed")
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	issuer, err := usecase.NewMentorRoleDecisionIssuer(privatePEM, publicPEM, sessionDouble{}, client, client)
	if err != nil {
		return errors.New("actual final Auth issuer construction failed")
	}
	pipe.mode = "normal"
	before := pipe.calls
	proof, err := issuer.Issue(ctx, "offline-owner-conformance", "offline-current-session", approve.MentorRoleDecisionRequest)
	if err != nil || proof == "" || pipe.calls-before != 2 {
		return errors.New("actual issuer did not confirm both real owner adapters")
	}
	if pipe.encoder.Encode(struct {
		Kind      string `json:"kind"`
		Proof     string `json:"proof"`
		PublicKey string `json:"public_key"`
	}{"grant_verify", proof, publicPEM}) != nil || !scanner.Scan() {
		return errors.New("final proof verification pipe unavailable")
	}
	var accepted struct {
		Accepted bool `json:"accepted"`
	}
	if json.Unmarshal(scanner.Bytes(), &accepted) != nil || !accepted.Accepted {
		return errors.New("actual RBAC final role-proof verifier rejected issuance")
	}
	checks++
	pipe.mode = "not_admin"
	before = pipe.calls
	if token, issueErr := issuer.Issue(ctx, "offline-owner-conformance", "offline-current-session", approve.MentorRoleDecisionRequest); token != "" || issueErr == nil || pipe.calls-before != 1 {
		return errors.New("issuer bypassed current Admin denial")
	}
	checks++
	pipe.mode = "suspended"
	before = pipe.calls
	if token, issueErr := issuer.Issue(ctx, "offline-owner-conformance", "offline-current-session", approve.MentorRoleDecisionRequest); token != "" || issueErr == nil || pipe.calls-before != 2 {
		return errors.New("issuer bypassed current Mentor state denial")
	}
	checks++
	return pipe.encoder.Encode(struct {
		Kind     string `json:"kind"`
		Status   string `json:"status"`
		Checks   int    `json:"checks"`
		Requests int    `json:"requests"`
	}{"summary", "PASS", checks, pipe.calls})
}

func main() {
	if err := exercise(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
