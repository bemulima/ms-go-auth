package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

const mentorOAuthActor = "10000000-0000-4000-8000-000000000001"

type mentorOAuthStore struct {
	mu       sync.Mutex
	client   domain.MCPMentorClient
	consents map[string]domain.MCPMentorConsent
	codes    map[string]domain.MCPMentorCode
	revoked  map[string]bool
	consumed map[string]bool
	active   bool
	creates  int
}

func (s *mentorOAuthStore) Client(_ context.Context, subject, client, resource string) (*domain.MCPMentorClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || subject != mentorOAuthActor || client != s.client.ID || resource != "https://api.example.test/mcp" {
		return nil, domain.ErrMCPMentorDenied
	}
	c := s.client
	return &c, nil
}
func (s *mentorOAuthStore) Consent(_ context.Context, subject, client, resource, id string, now time.Time) (*domain.MCPMentorConsent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return nil, domain.ErrNotFound
	}
	for key, c := range s.consents {
		if (id == "" || key == id) && !s.revoked[key] && c.MentorID == subject && c.ClientID == client && c.Resource == resource && c.ExpiresAt.After(now) {
			copy := c
			return &copy, nil
		}
	}
	return nil, domain.ErrNotFound
}
func (s *mentorOAuthStore) CreateGrant(_ context.Context, c domain.MCPMentorConsent, code domain.MCPMentorCode, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, old := range s.consents {
		if old.MentorID == c.MentorID && old.ClientID == c.ClientID && old.Resource == c.Resource {
			s.revoked[key] = true
		}
	}
	s.consents[c.ID] = c
	s.codes[code.Hash] = code
	s.creates++
	return nil
}
func (s *mentorOAuthStore) ConsumeCode(_ context.Context, hash, client, redirect, resource string, now time.Time) (*domain.MCPMentorCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[hash]
	if !ok || s.consumed[hash] || s.revoked[c.ConsentID] || !s.active || !c.ExpiresAt.After(now) || c.ClientID != client || c.RedirectURI != redirect || c.Resource != resource {
		return nil, domain.ErrMCPMentorDenied
	}
	s.consumed[hash] = true
	return &c, nil
}
func (s *mentorOAuthStore) Revoke(_ context.Context, subject, client, resource string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, c := range s.consents {
		if c.MentorID == subject && c.ClientID == client && c.Resource == resource {
			s.revoked[key] = true
		}
	}
	return nil
}

type mentorOAuthAuthority struct {
	mu        sync.Mutex
	err       error
	calls     int
	during    func()
	lastScope string
}

func (a *mentorOAuthAuthority) Check(ctx context.Context, subject, scope string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	a.lastScope = scope
	if a.during != nil {
		a.during()
	}
	if subject != mentorOAuthActor || !domain.ValidMCPMentorScope(scope) || ctx.Err() != nil {
		return domain.ErrMCPMentorDenied
	}
	return a.err
}

func mentorOAuthFixture(t *testing.T) (*MCPMentorOAuth, *mentorOAuthStore, *mentorOAuthAuthority, MCPMentorAuthorizationRequest, string, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	tokens, err := NewMCPMentorTokens("https://api.example.test/mentor", "https://api.example.test/mcp", privatePEM, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tokens.now = func() time.Time { return now }
	store := &mentorOAuthStore{client: domain.MCPMentorClient{ID: "mentor-client", Name: "Mentor desktop", RedirectURIs: []string{"https://client.example.test/callback?entry=mentor"}, Scopes: []string{domain.MCPMentorScope}}, consents: map[string]domain.MCPMentorConsent{}, codes: map[string]domain.MCPMentorCode{}, revoked: map[string]bool{}, consumed: map[string]bool{}, active: true}
	authority := &mentorOAuthAuthority{}
	u := &MCPMentorOAuth{Store: store, Authority: authority, Tokens: tokens, Resource: tokens.resource, AccessTTL: 5 * time.Minute, ConsentTTL: time.Hour, Clock: func() time.Time { return now }}
	verifier := strings.Repeat("A", 43)
	hash := sha256.Sum256([]byte(verifier))
	request := MCPMentorAuthorizationRequest{ResponseType: "code", ClientID: store.client.ID, RedirectURI: store.client.RedirectURIs[0], Resource: u.Resource, Challenge: base64.RawURLEncoding.EncodeToString(hash[:]), ChallengeMethod: "S256", Scope: domain.MCPMentorScope, State: strings.Repeat("S", 24)}
	return u, store, authority, request, verifier, privatePEM, publicPEM
}
func mentorOAuthCode(t *testing.T, u *MCPMentorOAuth, r MCPMentorAuthorizationRequest) string {
	t.Helper()
	callback, err := u.Approve(context.Background(), r, mentorOAuthActor)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(callback)
	if err != nil || parsed.Query().Get("state") != r.State || parsed.Query().Get("entry") != "mentor" || !validMCPAuthorizationCode(parsed.Query().Get("code")) {
		t.Fatal("unsafe callback")
	}
	return parsed.Query().Get("code")
}
func mentorOAuthExchangeRequest(r MCPMentorAuthorizationRequest, code, verifier string) MCPExternalTokenRequest {
	return MCPExternalTokenRequest{GrantType: "authorization_code", Code: code, Verifier: verifier, ClientID: r.ClientID, RedirectURI: r.RedirectURI, ResourceURI: r.Resource}
}

func TestMCPMentorOAuthExplicitConsentPKCEAndPerRequestRevocation(t *testing.T) {
	u, store, authority, request, verifier, _, _ := mentorOAuthFixture(t)
	ctx := context.Background()
	preview, err := u.Preview(ctx, request, mentorOAuthActor)
	if err != nil || preview.ConsentActive || preview.Persona != "MENTOR" || store.creates != 0 {
		t.Fatal("preview created or inferred consent")
	}
	code := mentorOAuthCode(t, u, request)
	if store.creates != 1 || authority.calls < 3 {
		t.Fatal("authorization skipped live authorities")
	}
	response, err := u.Exchange(ctx, mentorOAuthExchangeRequest(request, code, verifier))
	if err != nil || response.TokenType != "Bearer" || response.Scope != domain.MCPMentorScope || response.ExpiresIn != 300 {
		t.Fatalf("exchange: %v", err)
	}
	if _, err = u.Exchange(ctx, mentorOAuthExchangeRequest(request, code, verifier)); err != domain.ErrMCPMentorDenied {
		t.Fatal("code replay admitted")
	}
	before := authority.calls
	grant, err := u.Verify(ctx, response.AccessToken, u.Resource, u.now())
	if err != nil || grant.Persona != "MENTOR" || grant.MentorID != mentorOAuthActor || grant.OwnerProof == "" || len(grant.Scopes) != 1 || authority.calls != before+1 {
		t.Fatalf("verify: %v", err)
	}
	if err = u.Revoke(ctx, mentorOAuthActor, request.ClientID, u.Resource); err != nil {
		t.Fatal(err)
	}
	if _, err = u.Verify(ctx, response.AccessToken, u.Resource, u.now()); err != domain.ErrMCPMentorDenied {
		t.Fatal("revoked grant still usable")
	}
	// Revoke remains available after role loss and is idempotent.
	authority.err = domain.ErrMCPMentorDenied
	if err = u.Revoke(ctx, mentorOAuthActor, request.ClientID, u.Resource); err != nil {
		t.Fatal("role loss prevented disconnect")
	}
}
func TestMCPMentorOAuthWrongVerifierBurnsCodeAndReplayIsAtomic(t *testing.T) {
	u, _, _, r, verifier, _, _ := mentorOAuthFixture(t)
	code := mentorOAuthCode(t, u, r)
	if _, err := u.Exchange(context.Background(), mentorOAuthExchangeRequest(r, code, strings.Repeat("B", 43))); err != domain.ErrMCPMentorDenied {
		t.Fatal("wrong PKCE accepted")
	}
	if _, err := u.Exchange(context.Background(), mentorOAuthExchangeRequest(r, code, verifier)); err != domain.ErrMCPMentorDenied {
		t.Fatal("bad verifier did not burn code")
	}
	code = mentorOAuthCode(t, u, r)
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := u.Exchange(context.Background(), mentorOAuthExchangeRequest(r, code, verifier))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful redemptions=%d", success)
	}
}
func TestMCPMentorOAuthNoRoleClientOrConsentFallback(t *testing.T) {
	u, store, authority, r, verifier, _, _ := mentorOAuthFixture(t)
	for _, scope := range []string{"profile:read", "courses:read", "mentor:profile:read profile:read", "mentor:profile:write", "mentor:courses:read"} {
		bad := r
		bad.Scope = scope
		if _, err := u.Approve(context.Background(), bad, mentorOAuthActor); err != domain.ErrMCPMentorDenied {
			t.Fatalf("scope admitted: %q", scope)
		}
	}
	if store.creates != 0 {
		t.Fatal("denied scope wrote consent")
	}
	code := mentorOAuthCode(t, u, r)
	authority.err = domain.ErrMCPMentorDenied
	if _, err := u.Exchange(context.Background(), mentorOAuthExchangeRequest(r, code, verifier)); err != domain.ErrMCPMentorDenied {
		t.Fatal("suspended role issued token")
	}
	authority.err = nil
	if _, err := u.Exchange(context.Background(), mentorOAuthExchangeRequest(r, code, verifier)); err != domain.ErrMCPMentorDenied {
		t.Fatal("role recovery replayed consumed code")
	}
	code = mentorOAuthCode(t, u, r)
	response, err := u.Exchange(context.Background(), mentorOAuthExchangeRequest(r, code, verifier))
	if err != nil {
		t.Fatal(err)
	}
	authority.during = func() { _ = store.Revoke(context.Background(), mentorOAuthActor, r.ClientID, u.Resource) }
	if _, err = u.Verify(context.Background(), response.AccessToken, u.Resource, u.now()); err != domain.ErrMCPMentorDenied {
		t.Fatal("consent revoked during remote I/O was accepted")
	}
	authority.during = nil
	authority.err = domain.ErrMCPMentorUnavailable
	if _, err = u.Approve(context.Background(), r, mentorOAuthActor); err != domain.ErrMCPMentorUnavailable {
		t.Fatal("owner outage became permission")
	}
}
func TestMCPMentorTokensStrictPersonaAndCrossTokenDenial(t *testing.T) {
	u, _, _, r, verifier, privatePEM, publicPEM := mentorOAuthFixture(t)
	code := mentorOAuthCode(t, u, r)
	response, err := u.Exchange(context.Background(), mentorOAuthExchangeRequest(r, code, verifier))
	if err != nil {
		t.Fatal(err)
	}
	base, err := u.Tokens.VerifyAccess(response.AccessToken, u.Resource)
	if err != nil {
		t.Fatal(err)
	}
	student, err := NewMCPExternalAccessJWTAuthority("https://api.example.test", u.Resource, privatePEM, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	student.now = u.Clock
	if _, err = student.VerifySignature(response.AccessToken, u.Resource); err == nil {
		t.Fatal("Mentor token admitted by Student verifier")
	}
	studentJWT, err := student.Sign(&MCPExternalAccessTokenIntent{Issuer: "https://api.example.test", Subject: mentorOAuthActor, Audience: u.Resource, ClientID: r.ClientID, GrantID: base.GrantID, Scope: "profile:read", JWTID: strings.Repeat("A", 43), IssuedAt: u.now().Unix(), ExpiresAt: u.now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = u.Tokens.VerifyAccess(studentJWT, u.Resource); err == nil {
		t.Fatal("Student token admitted by Mentor verifier")
	}
	for _, test := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong persona", func(c map[string]any) { c["persona"] = "STUDENT" }},
		{"Student scope", func(c map[string]any) { c["scope"] = "profile:read" }},
		{"mixed scopes", func(c map[string]any) { c["scope"] = "mentor:profile:read profile:read" }},
		{"wrong audience", func(c map[string]any) { c["aud"] = "https://other.example.test/mcp" }},
		{"array audience", func(c map[string]any) { c["aud"] = []string{u.Resource} }},
		{"missing persona", func(c map[string]any) { delete(c, "persona") }},
		{"role claim", func(c map[string]any) { c["role"] = "admin" }},
		{"future issued", func(c map[string]any) { c["iat"] = u.now().Add(time.Second).Unix() }},
		{"excess lifetime", func(c map[string]any) { c["exp"] = u.now().Add(301 * time.Second).Unix() }},
		{"expired", func(c map[string]any) { c["exp"] = u.now().Unix() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, _ := json.Marshal(base)
			var claims map[string]any
			_ = json.Unmarshal(data, &claims)
			test.edit(claims)
			token, err := u.Tokens.sign(domain.MCPMentorAccessType, claims)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = u.Tokens.VerifyAccess(token, u.Resource); err == nil {
				t.Fatal("invalid signed claims admitted")
			}
		})
	}
	// Web sessions and purpose-specific internal delegations cannot be tokens.
	web := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": mentorOAuthActor, "iss": u.Tokens.issuer, "aud": u.Resource, "exp": u.now().Add(time.Minute).Unix()})
	raw, _ := web.SignedString(u.Tokens.private)
	approval, _ := u.Tokens.ApprovalProof(mentorOAuthActor)
	profile, _ := u.Tokens.ProfileProof(*base)
	for _, raw := range []string{raw, approval, profile} {
		if _, err = u.Tokens.VerifyAccess(raw, u.Resource); err == nil {
			t.Fatal("non-access credential admitted")
		}
	}
	if _, err = u.Tokens.VerifyAccess(response.AccessToken, "https://other.example.test/mcp"); err == nil {
		t.Fatal("wrong requested resource admitted")
	}
}
func TestMCPMentorExactObjectRejectsAliasesAndDuplicates(t *testing.T) {
	for _, data := range []string{`{"sub":"a","sub":"b"}`, `{"s\u0075b":"a"}`, `{"Sub":"a"}`, `{"sub":null}`, `{"sub":"a"} {}`, "{\"sub\":\"\xff\"}"} {
		var target struct {
			Subject string `json:"sub"`
		}
		if mcpMentorObject([]byte(data), []string{"sub"}, &target) == nil {
			t.Fatalf("accepted malformed JSON: %q", data)
		}
	}
}

func TestMCPMentorOffersConsentAndProofAreScopeBound(t *testing.T) {
	oauth, store, authority, profile, verifier, _, _ := mentorOAuthFixture(t)
	ctx := context.Background()
	offers := profile
	offers.Scope = domain.MCPMentorOffersScope
	store.client.Scopes = append(store.client.Scopes, offers.Scope)
	if _, err := oauth.Preview(ctx, offers, mentorOAuthActor); err != domain.ErrMCPMentorDenied {
		t.Fatalf("offers enabled by default: %v", err)
	}
	oauth.OffersEnabled = true
	profileToken, err := oauth.Exchange(ctx, mentorOAuthExchangeRequest(profile, mentorOAuthCode(t, oauth, profile), verifier))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := oauth.Preview(ctx, offers, mentorOAuthActor)
	if err != nil || preview.ConsentActive || len(preview.Scopes) != 1 || preview.Scopes[0] != offers.Scope {
		t.Fatalf("profile consent substituted for offers: %+v %v", preview, err)
	}
	offerToken, err := oauth.Exchange(ctx, mentorOAuthExchangeRequest(offers, mentorOAuthCode(t, oauth, offers), verifier))
	if err != nil || offerToken.Scope != offers.Scope || authority.lastScope != offers.Scope {
		t.Fatalf("wrong scope in token or role check: %v", err)
	}
	if _, err = oauth.Verify(ctx, profileToken.AccessToken, oauth.Resource, oauth.now()); err != domain.ErrMCPMentorDenied {
		t.Fatalf("prior client grant survived replacement: %v", err)
	}
	grant, err := oauth.Verify(ctx, offerToken.AccessToken, oauth.Resource, oauth.now())
	if err != nil || len(grant.Scopes) != 1 || grant.Scopes[0] != offers.Scope {
		t.Fatalf("offers token did not verify: %v", err)
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.Split(grant.OwnerProof, ".")[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(body, &claims) != nil || claims["scope"] != offers.Scope || claims["purpose"] != domain.MCPMentorOffersPurpose {
		t.Fatal("owner proof substituted a different purpose or scope")
	}
	oauth.OffersEnabled = false
	if _, err = oauth.Verify(ctx, offerToken.AccessToken, oauth.Resource, oauth.now()); err != domain.ErrMCPMentorDenied {
		t.Fatalf("offers token survived switch-off: %v", err)
	}
}

func TestMCPMentorWorkspaceConsentUsesExactScope(t *testing.T) {
	oauth, store, authority, request, verifier, _, _ := mentorOAuthFixture(t)
	ctx := context.Background()
	store.client.Scopes = append(store.client.Scopes, domain.MCPMentorWorkspaceReadScopes()...)
	for _, scope := range domain.MCPMentorWorkspaceReadScopes() {
		t.Run(scope, func(t *testing.T) {
			request.Scope = scope
			if _, err := oauth.Preview(ctx, request, mentorOAuthActor); err != domain.ErrMCPMentorDenied {
				t.Fatalf("disabled workspace scope preview: %v", err)
			}
			oauth.WorkspaceReadEnabled = true
			preview, err := oauth.Preview(ctx, request, mentorOAuthActor)
			if err != nil || preview.ConsentActive || len(preview.Scopes) != 1 || preview.Scopes[0] != scope {
				t.Fatalf("another scope changed workspace consent: %+v %v", preview, err)
			}
			token, err := oauth.Exchange(ctx, mentorOAuthExchangeRequest(request, mentorOAuthCode(t, oauth, request), verifier))
			if err != nil || token.Scope != scope || authority.lastScope != scope {
				t.Fatalf("workspace scope did not reach token exchange and RBAC: %v", err)
			}
			grant, err := oauth.Verify(ctx, token.AccessToken, oauth.Resource, oauth.now())
			if err != nil || len(grant.Scopes) != 1 || grant.Scopes[0] != scope {
				t.Fatalf("workspace scope did not reach verification: %v", err)
			}
			oauth.WorkspaceReadEnabled = false
			if _, err := oauth.Verify(ctx, token.AccessToken, oauth.Resource, oauth.now()); err != domain.ErrMCPMentorDenied {
				t.Fatalf("workspace granted after switch-off: %v", err)
			}
		})
	}
}

func TestMCPMentorSkillDraftDelegationNeedsSeparateEnabledScope(t *testing.T) {
	oauth, store, authority, request, verifier, _, _ := mentorOAuthFixture(t)
	ctx := context.Background()
	request.Scope = domain.MCPMentorSkillDraftScope
	store.client.Scopes = append(store.client.Scopes, request.Scope)
	oauth.WorkspaceReadEnabled = true
	if _, err := oauth.Preview(ctx, request, mentorOAuthActor); err != domain.ErrMCPMentorDenied {
		t.Fatalf("read feature admitted unrelated draft authority: %v", err)
	}
	oauth.SkillDraftEnabled = true
	token, err := oauth.Exchange(ctx, mentorOAuthExchangeRequest(request, mentorOAuthCode(t, oauth, request), verifier))
	if err != nil || token.Scope != request.Scope || authority.lastScope != request.Scope {
		t.Fatalf("draft authority reached wrong RBAC scope or token: %v", err)
	}
	grant, err := oauth.Verify(ctx, token.AccessToken, oauth.Resource, oauth.now())
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(grant.OwnerProof, ".")[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(claimsJSON, &claims) != nil || claims["scope"] != request.Scope || claims["purpose"] != domain.MCPMentorSkillDraftPurpose {
		t.Fatal("draft proof did not bind the owner purpose")
	}
	oauth.SkillDraftEnabled = false
	if _, err := oauth.Verify(ctx, token.AccessToken, oauth.Resource, oauth.now()); err != domain.ErrMCPMentorDenied {
		t.Fatalf("draft access survived switch-off: %v", err)
	}
}
