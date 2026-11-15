package usecase

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
)

// This fake tests the use-case contract; it is NOT a replacement for the
// PostgreSQL conditional-UPDATE concurrency and consent-revocation gates.
type fakeMCPExternalCodeStore struct {
	mu          sync.Mutex
	value       *domain.MCPExternalAuthorizationCode
	consumed    bool
	failCreate  bool
	failConsume bool
}

func (f *fakeMCPExternalCodeStore) CreateMCPExternalCode(_ context.Context, code *domain.MCPExternalAuthorizationCode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCreate || f.value != nil {
		return errors.New("simulated persistence refusal")
	}
	copyOfCode := *code
	copyOfCode.Scopes = append([]string(nil), code.Scopes...)
	f.value = &copyOfCode
	return nil
}

func (f *fakeMCPExternalCodeStore) ConsumeMCPExternalCode(
	_ context.Context, hash, client, redirect, resource string, now time.Time,
) (*domain.MCPExternalAuthorizationCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failConsume || f.consumed || f.value == nil ||
		f.value.CodeHash != hash || f.value.ClientID != client ||
		f.value.RedirectURI != redirect || f.value.ResourceURI != resource ||
		!f.value.ExpiresAt.After(now) {
		return nil, domain.ErrNotFound
	}
	f.consumed = true
	copyOfCode := *f.value
	copyOfCode.Scopes = append([]string(nil), f.value.Scopes...)
	return &copyOfCode, nil
}

func newMCPCodeFixture(t *testing.T) (MCPExternalCodeUsecase, *fakeMCPExternalCodeStore, MCPExternalPolicy, MCPExternalAuthorizationRequest, MCPExternalClient, MCPExternalConsent, string, time.Time) {
	t.Helper()
	policy, request, client, consent, student, now := baseMCPExternalFixture()
	consent.ID = "11111111-1111-4111-8111-111111111111"
	store := &fakeMCPExternalCodeStore{}
	return MCPExternalCodeUsecase{Codes: store, TTL: 5 * time.Minute}, store, policy, request, client, consent, student, now
}

func TestMCPExternalCodeIssueAndSingleUseRedeem(t *testing.T) {
	ctx := context.Background()
	svc, store, policy, req, client, consent, student, now := newMCPCodeFixture(t)
	code, err := svc.Issue(ctx, policy, req, client, consent, student, now)
	if err != nil || !validMCPAuthorizationCode(code) {
		t.Fatalf("expected a strong authorization code, code valid=%v err=%v", validMCPAuthorizationCode(code), err)
	}
	if store.value == nil || store.value.CodeHash == code || len(store.value.CodeHash) != 64 ||
		store.value.StudentID != student || store.value.ConsentID != consent.ID ||
		store.value.ResourceURI != policy.ResourceURI || store.value.ClientID != client.ID ||
		store.value.RedirectURI != req.RedirectURI || store.value.CodeChallenge != rfc7636Challenge {
		t.Fatal("missing hash-only immutable authorization-code binding")
	}
	// The consent expires after one hour, but code TTL is capped at five minutes.
	if !store.value.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("unexpected code expiry: %v", store.value.ExpiresAt)
	}
	issued, err := svc.Redeem(ctx, code, rfc7636Verifier, client.ID, req.RedirectURI, policy.ResourceURI, now.Add(time.Second))
	if err != nil || issued == nil || issued.StudentID != student ||
		!reflect.DeepEqual(issued.Scopes, []string{"courses:read", "lessons:read"}) {
		t.Fatalf("valid grant denied or unbound: %+v %v", issued, err)
	}
	if again, err := svc.Redeem(ctx, code, rfc7636Verifier, client.ID, req.RedirectURI, policy.ResourceURI, now.Add(time.Second)); again != nil || err != ErrMCPExternalDenied {
		t.Fatalf("one-time code was reusable: %+v %v", again, err)
	}
}

func TestMCPExternalCodeWrongBindingsDoNotBurnCorrectCode(t *testing.T) {
	ctx := context.Background()
	svc, _, policy, req, client, consent, student, now := newMCPCodeFixture(t)
	code, err := svc.Issue(ctx, policy, req, client, consent, student, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		name, client, redirect, resource, verifier string
	}{
		{"other-client", "other-app", req.RedirectURI, policy.ResourceURI, rfc7636Verifier},
		{"other-redirect", client.ID, "https://other.example.test/callback", policy.ResourceURI, rfc7636Verifier},
		{"other-audience", client.ID, req.RedirectURI, "https://other.example.test/mcp", rfc7636Verifier},
		{"malformed-verifier", client.ID, req.RedirectURI, policy.ResourceURI, "short"},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			got, err := svc.Redeem(ctx, code, attempt.verifier, attempt.client, attempt.redirect, attempt.resource, now)
			if got != nil || err != ErrMCPExternalDenied {
				t.Fatalf("unexpected grant: %+v %v", got, err)
			}
		})
	}
	if _, err := svc.Redeem(ctx, code, rfc7636Verifier, client.ID, req.RedirectURI, policy.ResourceURI, now); err != nil {
		t.Fatalf("unrelated failed bindings destroyed the legitimate code: %v", err)
	}
}

func TestMCPExternalCodeWrongWellFormedPKCEBurnsCode(t *testing.T) {
	ctx := context.Background()
	svc, store, policy, req, client, consent, student, now := newMCPCodeFixture(t)
	code, err := svc.Issue(ctx, policy, req, client, consent, student, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Redeem(ctx, code, strings.Repeat("b", 43), client.ID, req.RedirectURI, policy.ResourceURI, now); got != nil || err != ErrMCPExternalDenied {
		t.Fatalf("wrong verifier accepted: %+v %v", got, err)
	}
	if !store.consumed {
		t.Fatal("wrong well-formed PKCE verifier did not burn the code")
	}
	if got, err := svc.Redeem(ctx, code, rfc7636Verifier, client.ID, req.RedirectURI, policy.ResourceURI, now); got != nil || err != ErrMCPExternalDenied {
		t.Fatalf("burned code replay accepted: %+v %v", got, err)
	}
}

func TestMCPExternalCodeConcurrentRedeemAtMostOne(t *testing.T) {
	ctx := context.Background()
	svc, _, policy, req, client, consent, student, now := newMCPCodeFixture(t)
	code, err := svc.Issue(ctx, policy, req, client, consent, student, now)
	if err != nil {
		t.Fatal(err)
	}
	var successful atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Redeem(ctx, code, rfc7636Verifier, client.ID, req.RedirectURI, policy.ResourceURI, now); err == nil {
				successful.Add(1)
			} else if err != ErrMCPExternalDenied {
				t.Errorf("non-uniform denial: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := successful.Load(); n != 1 {
		t.Fatalf("redemptions=%d, want exactly one", n)
	}
}

func TestMCPExternalCodeFailClosedOnConsentAndRepository(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		change func(*MCPExternalCodeUsecase, *fakeMCPExternalCodeStore, *MCPExternalConsent)
	}{
		{"unpersisted-consent", func(_ *MCPExternalCodeUsecase, _ *fakeMCPExternalCodeStore, c *MCPExternalConsent) { c.ID = "" }},
		{"revoked-consent", func(_ *MCPExternalCodeUsecase, _ *fakeMCPExternalCodeStore, c *MCPExternalConsent) { c.Revoked = true }},
		{"no-repository", func(s *MCPExternalCodeUsecase, _ *fakeMCPExternalCodeStore, _ *MCPExternalConsent) { s.Codes = nil }},
		{"excessive-ttl", func(s *MCPExternalCodeUsecase, _ *fakeMCPExternalCodeStore, _ *MCPExternalConsent) { s.TTL = 6 * time.Minute }},
		{"repository-refusal", func(_ *MCPExternalCodeUsecase, f *fakeMCPExternalCodeStore, _ *MCPExternalConsent) { f.failCreate = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, store, policy, req, client, consent, student, now := newMCPCodeFixture(t)
			tc.change(&svc, store, &consent)
			code, err := svc.Issue(ctx, policy, req, client, consent, student, now)
			if code != "" || err != ErrMCPExternalDenied || store.value != nil {
				t.Fatalf("not fail-closed: issued=%v err=%v", code != "", err)
			}
		})
	}
}

func TestMCPExternalCodeExpiryAndStorageFailure(t *testing.T) {
	ctx := context.Background()
	svc, store, policy, req, client, consent, student, now := newMCPCodeFixture(t)
	code, err := svc.Issue(ctx, policy, req, client, consent, student, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Redeem(ctx, code, rfc7636Verifier, client.ID, req.RedirectURI, policy.ResourceURI, now.Add(5*time.Minute)); got != nil || err != ErrMCPExternalDenied {
		t.Fatalf("expired code accepted: %+v %v", got, err)
	}
	store.failConsume = true
	if got, err := svc.Redeem(ctx, code, rfc7636Verifier, client.ID, req.RedirectURI, policy.ResourceURI, now); got != nil || err != ErrMCPExternalDenied {
		t.Fatalf("storage failure exposed/accepted: %+v %v", got, err)
	}
}
