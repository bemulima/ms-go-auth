//go:build mentortransportconformance

// Test-only HTTPS owner bridge, excluded from normal builds. Access-token
// verification, strict-session admission, HTTP handling and role signing are
// actual production components. Persistence and owner confirmations are
// controlled fixtures. Stdout is a private pipe, never a diagnostic log.
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
	"io"
	"log"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	internalhttp "github.com/example/auth-service/internal/transport/http/private"
	"github.com/example/auth-service/internal/usecase"
)

const (
	actorID   = "11111111-1111-4111-8111-111111111111"
	targetID  = "22222222-2222-4222-8222-222222222222"
	appID     = "33333333-3333-4333-8333-333333333333"
	sessionID = "44444444-4444-4444-8444-444444444444"
	approveID = "55555555-5555-4555-8555-555555555555"
	suspendID = "77777777-7777-4777-8777-777777777777"
)

type fixture struct {
	mu   sync.RWMutex
	mode string
}

func (f *fixture) current() string { f.mu.RLock(); defer f.mu.RUnlock(); return f.mode }
func (f *fixture) FindActive(ctx context.Context, key string) (*domain.RefreshToken, error) {
	mode := f.current()
	if ctx.Err() != nil || mode == "session_outage" {
		return nil, errors.New("controlled session dependency failure")
	}
	if key != "rt:"+sessionID || mode == "revoked" {
		return nil, domain.ErrNotFound
	}
	return &domain.RefreshToken{UserID: actorID, RefreshTokenHash: key, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (f *fixture) ConfirmCanonicalAdmin(ctx context.Context, actor string) (*domain.CanonicalAdminConfirmation, error) {
	mode := f.current()
	if ctx.Err() != nil || mode == "admin_outage" {
		return nil, errors.New("controlled Admin dependency failure")
	}
	return &domain.CanonicalAdminConfirmation{ActorID: actor, UniqueCanonicalDefaultAdmin: actor == actorID && mode != "nonadmin"}, nil
}
func expected(decision string, revision int64, request string) domain.MentorRoleDecisionBinding {
	digest := sha256.Sum256([]byte(decision + "|" + actorID + "|" + appID + "|" + request + "|" + strconv.FormatInt(revision-1, 10)))
	return domain.MentorRoleDecisionBinding{AdminActorID: actorID, MentorRoleDecisionRequest: domain.MentorRoleDecisionRequest{
		TargetUserID: targetID, ApplicationID: appID, ApplicationRevision: revision, Decision: decision, RequestID: request, DecisionDigest: hex.EncodeToString(digest[:]),
	}}
}
func (f *fixture) ConfirmCommittedMentorIntent(ctx context.Context, binding domain.MentorRoleDecisionBinding) (*domain.MentorCommittedIntentConfirmation, error) {
	mode := f.current()
	if ctx.Err() != nil || mode == "intent_outage" {
		return nil, errors.New("controlled intent dependency failure")
	}
	want, state := expected("APPROVE", 2, approveID), domain.MentorApprovalPendingGrant
	if mode == "suspend" {
		want, state = expected("SUSPEND", 4, suspendID), domain.MentorSuspended
	}
	return &domain.MentorCommittedIntentConfirmation{Binding: binding, Committed: true, Current: mode != "stale" && binding == want, State: state}, nil
}
func keys() (string, string, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	p, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p})), nil
}
func run() error {
	accessPrivate, accessPublic, err := keys()
	if err != nil {
		return err
	}
	rolePrivate, rolePublic, err := keys()
	if err != nil {
		return err
	}
	signer, err := usecase.NewJWTSigner(&config.Config{JWTPrivateKey: accessPrivate, JWTPublicKey: accessPublic, JWTIssuer: "mentor-transport-fixture", JWTAudience: "mentor-transport-fixture"})
	if err != nil {
		return err
	}
	bearer, err := signer.SignAccessToken(actorID, map[string]any{"sid": sessionID, "role": "admin"}, time.Minute)
	if err != nil {
		return err
	}
	f := &fixture{mode: "approve"}
	sessions, err := usecase.NewMentorLiveSessionVerifier(signer, f)
	if err != nil {
		return err
	}
	authority, err := usecase.NewMentorHTTPAuthority(rolePrivate, rolePublic, sessions, f, f)
	if err != nil {
		return err
	}
	handler, err := internalhttp.NewMentorHTTPAuthorityHandler(authority)
	if err != nil {
		return err
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ReadHeaderTimeout = 3 * time.Second
	server.Config.ReadTimeout = 3 * time.Second
	server.Config.WriteTimeout = 3 * time.Second
	server.StartTLS()
	defer server.Close()
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(struct {
		Origin string `json:"origin"`
		CA     string `json:"ca"`
		Public string `json:"public_key"`
		Bearer string `json:"bearer"`
	}{
		server.URL, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), rolePublic, bearer,
	}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 65536)
	for count := 0; scanner.Scan(); count++ {
		var command struct {
			Mode string `json:"mode"`
		}
		if count > 100 || json.Unmarshal(scanner.Bytes(), &command) != nil {
			return errors.New("invalid fixture control")
		}
		switch command.Mode {
		case "approve", "suspend", "stale", "intent_outage", "revoked", "session_outage", "nonadmin", "admin_outage":
		default:
			return errors.New("invalid fixture mode")
		}
		f.mu.Lock()
		f.mode = command.Mode
		f.mu.Unlock()
		if err := out.Encode(struct {
			OK bool `json:"ok"`
		}{true}); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func main() {
	guard := time.AfterFunc(45*time.Second, func() { os.Exit(2) })
	defer guard.Stop()
	if run() != nil {
		os.Stderr.WriteString("Auth transport fixture failed; details withheld\n")
		os.Exit(1)
	}
}
