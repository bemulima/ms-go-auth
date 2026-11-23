//go:build mentorconformance

// This offline test bridge is excluded from normal builds. Its stdout is a
// private pipe consumed by the conformance runner, never a diagnostic log.
package main

import (
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
	"github.com/example/auth-service/internal/usecase"
)

const (
	adminID                = "11111111-1111-4111-8111-111111111111"
	targetID               = "22222222-2222-4222-8222-222222222222"
	applicationID          = "33333333-3333-4333-8333-333333333333"
	sessionID              = "44444444-4444-4444-8444-444444444444"
	approveRequest         = "55555555-5555-4555-8555-555555555555"
	suspendPendingRequest  = "66666666-6666-4666-8666-666666666666"
	suspendApprovedRequest = "77777777-7777-4777-8777-777777777777"
	fixtureSession         = "offline-conformance-session-double"
)

// Only wire signing is real here. Session, RBAC and Mentor owner ports are
// explicit test doubles, not evidence of a mounted or authenticated transport.
type sessionDouble struct{}

func (sessionDouble) VerifyToken(_ context.Context, _, token string) (*usecase.VerificationResult, error) {
	if token != fixtureSession {
		return nil, errors.New("fixture session denied")
	}
	return &usecase.VerificationResult{UserID: adminID, Claims: map[string]any{"sid": sessionID}}, nil
}

type adminDouble struct{}

func (adminDouble) ConfirmCanonicalAdmin(_ context.Context, actor string) (*domain.CanonicalAdminConfirmation, error) {
	return &domain.CanonicalAdminConfirmation{ActorID: actor, UniqueCanonicalDefaultAdmin: actor == adminID}, nil
}

type intentDouble struct{}

func (intentDouble) ConfirmCommittedMentorIntent(_ context.Context, binding domain.MentorRoleDecisionBinding) (*domain.MentorCommittedIntentConfirmation, error) {
	state := domain.MentorApprovalPendingGrant
	if binding.Decision == "SUSPEND" {
		state = domain.MentorSuspended
	}
	return &domain.MentorCommittedIntentConfirmation{Binding: binding, Committed: true, Current: true, State: state}, nil
}

type envelope struct {
	PublicKey string            `json:"public_key"`
	Proofs    map[string]string `json:"proofs"`
}

func request(decision string, revision int64, requestID string) domain.MentorRoleDecisionRequest {
	digest := sha256.Sum256([]byte(decision + "|" + adminID + "|" + applicationID + "|" + requestID + "|" + strconv.FormatInt(revision-1, 10)))
	return domain.MentorRoleDecisionRequest{TargetUserID: targetID, ApplicationID: applicationID, ApplicationRevision: revision, Decision: decision, RequestID: requestID, DecisionDigest: hex.EncodeToString(digest[:])}
}

func produce() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.New("ephemeral key generation failed")
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return errors.New("ephemeral public key encoding failed")
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	issuer, err := usecase.NewMentorRoleDecisionIssuer(privatePEM, publicPEM, sessionDouble{}, adminDouble{}, intentDouble{})
	if err != nil {
		return errors.New("actual Auth issuer construction failed")
	}
	requests := map[string]domain.MentorRoleDecisionRequest{
		"approve":          request("APPROVE", 2, approveRequest),
		"approve_retry":    request("APPROVE", 2, approveRequest),
		"suspend_pending":  request("SUSPEND", 3, suspendPendingRequest),
		"suspend_approved": request("SUSPEND", 4, suspendApprovedRequest),
	}
	out := envelope{PublicKey: publicPEM, Proofs: make(map[string]string, len(requests))}
	for name, req := range requests {
		proof, issueErr := issuer.Issue(context.Background(), "offline-mentor-conformance", fixtureSession, req)
		if issueErr != nil || proof == "" {
			return fmt.Errorf("actual Auth issuer denied fixture %s", name)
		}
		out.Proofs[name] = proof
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func main() {
	if err := produce(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
