package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"time"

	"github.com/example/auth-service/internal/domain"
)

type MCPMentorAuthority interface {
	Check(context.Context, string) error
}
type MCPMentorLiveAuthority struct {
	Tokens *MCPMentorTokens
	RBAC   domain.MCPMentorRBACClient
	Owner  domain.MCPMentorApprovalClient
}

func (a MCPMentorLiveAuthority) Check(ctx context.Context, subject string) error {
	if ctx == nil || ctx.Err() != nil || a.Tokens == nil || a.RBAC == nil || a.Owner == nil || !validNonZeroCanonicalMCPUUID(subject) {
		return domain.ErrMCPMentorUnavailable
	}
	started := a.Tokens.now().UTC()
	proof, nonce, err := a.Tokens.RBACProof(subject)
	if err != nil {
		return domain.ErrMCPMentorUnavailable
	}
	allowed, err := a.RBAC.CheckMCPMentorAccess(ctx, proof, subject, nonce)
	if err != nil || ctx.Err() != nil {
		return domain.ErrMCPMentorUnavailable
	}
	if !allowed {
		return domain.ErrMCPMentorDenied
	}
	proof, err = a.Tokens.ApprovalProof(subject)
	if err != nil {
		return domain.ErrMCPMentorUnavailable
	}
	if err = a.Owner.Approved(ctx, proof, subject); err != nil {
		return err
	}
	finished := a.Tokens.now().UTC()
	if ctx.Err() != nil || finished.Before(started) || finished.Sub(started) >= 15*time.Second {
		return domain.ErrMCPMentorUnavailable
	}
	return nil
}

type MCPMentorAuthorizationRequest struct {
	ResponseType    string `json:"response_type"`
	ClientID        string `json:"client_id"`
	RedirectURI     string `json:"redirect_uri"`
	Resource        string `json:"resource"`
	Challenge       string `json:"code_challenge"`
	ChallengeMethod string `json:"code_challenge_method"`
	Scope           string `json:"scope"`
	State           string `json:"state"`
}
type MCPMentorConsentPreview struct {
	Persona          string     `json:"persona"`
	ClientID         string     `json:"client_id"`
	ClientName       string     `json:"client_name"`
	Resource         string     `json:"resource"`
	Scopes           []string   `json:"scopes"`
	ConsentActive    bool       `json:"consent_active"`
	ConsentExpiresAt *time.Time `json:"consent_expires_at,omitempty"`
}
type MCPMentorTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}
type MCPMentorVerifiedGrant struct {
	Persona    string   `json:"persona"`
	MentorID   string   `json:"mentor_id"`
	ClientID   string   `json:"client_id"`
	GrantID    string   `json:"grant_id"`
	Audience   string   `json:"audience"`
	Scopes     []string `json:"scopes"`
	ExpiresAt  int64    `json:"expires_at"`
	OwnerProof string   `json:"owner_proof"`
}
type MCPMentorOAuth struct {
	Store                 domain.MCPMentorStore
	Authority             MCPMentorAuthority
	Tokens                *MCPMentorTokens
	Resource              string
	AccessTTL, ConsentTTL time.Duration
	Clock                 func() time.Time
}

func (u *MCPMentorOAuth) now() time.Time {
	if u.Clock != nil {
		return u.Clock().UTC()
	}
	return time.Now().UTC()
}
func (u *MCPMentorOAuth) configured() bool {
	return u != nil && u.Store != nil && u.Authority != nil && u.Tokens != nil && validMCPResourceURI(u.Resource) && u.Resource == u.Tokens.resource && u.AccessTTL >= time.Second && u.AccessTTL <= 5*time.Minute && u.ConsentTTL >= u.AccessTTL && u.ConsentTTL <= 24*time.Hour
}

// Shape validation is also used before redirecting to the first-party UI.
// Identity and registered-client/current-authority checks happen at consent.
func ValidMCPMentorAuthorizationRequest(r MCPMentorAuthorizationRequest, resource string) bool {
	callback, err := url.Parse(r.RedirectURI)
	if err != nil || callback.Query().Has("refresh_token") {
		return false
	}
	return validMCPResourceURI(resource) && r.Resource == resource && r.ResponseType == "code" && validMCPMentorClientID(r.ClientID) && validMCPRedirectURI(r.RedirectURI) && len(r.RedirectURI) <= 2048 && redirectQuerySafeForCode(r.RedirectURI) && r.ChallengeMethod == "S256" && validMCPCodeChallenge(r.Challenge) && r.Scope == domain.MCPMentorScope && validMCPExternalState(r.State)
}
func (u *MCPMentorOAuth) admitted(ctx context.Context, r MCPMentorAuthorizationRequest, subject string) (*domain.MCPMentorClient, error) {
	if !u.configured() || ctx == nil || ctx.Err() != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	if !validNonZeroCanonicalMCPUUID(subject) || !ValidMCPMentorAuthorizationRequest(r, u.Resource) {
		return nil, domain.ErrMCPMentorDenied
	}
	client, err := u.Store.Client(ctx, subject, r.ClientID, u.Resource)
	if err != nil {
		return nil, err
	}
	if client == nil || client.ID != r.ClientID || len(client.Scopes) != 1 || client.Scopes[0] != domain.MCPMentorScope || !registeredMCPRedirect(r.RedirectURI, client.RedirectURIs) {
		return nil, domain.ErrMCPMentorDenied
	}
	if err = u.Authority.Check(ctx, subject); err != nil {
		return nil, err
	}
	return client, nil
}
func (u *MCPMentorOAuth) Preview(ctx context.Context, r MCPMentorAuthorizationRequest, subject string) (*MCPMentorConsentPreview, error) {
	client, err := u.admitted(ctx, r, subject)
	if err != nil {
		return nil, err
	}
	preview := &MCPMentorConsentPreview{Persona: domain.MCPMentorPersona, ClientID: client.ID, ClientName: client.Name, Resource: u.Resource, Scopes: []string{domain.MCPMentorScope}}
	consent, err := u.Store.Consent(ctx, subject, client.ID, u.Resource, "", u.now())
	if err != nil && err != domain.ErrNotFound {
		return nil, err
	}
	if consent != nil {
		preview.ConsentActive = true
		expiry := consent.ExpiresAt
		preview.ConsentExpiresAt = &expiry
	}
	if ctx.Err() != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	return preview, nil
}

// Approve is the only consent writer. The first-party session-bound UI must
// explicitly submit it; authorization GET and preview never create a grant.
func (u *MCPMentorOAuth) Approve(ctx context.Context, r MCPMentorAuthorizationRequest, subject string) (string, error) {
	if _, err := u.admitted(ctx, r, subject); err != nil {
		return "", err
	}
	now := u.now()
	id, err := GenerateJTI()
	if err != nil {
		return "", domain.ErrMCPMentorUnavailable
	}
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return "", domain.ErrMCPMentorUnavailable
	}
	code := base64.RawURLEncoding.EncodeToString(entropy[:])
	hash := sha256.Sum256([]byte(code))
	consent := domain.MCPMentorConsent{ID: id, MentorID: subject, ClientID: r.ClientID, Resource: u.Resource, ExpiresAt: now.Add(u.ConsentTTL)}
	record := domain.MCPMentorCode{Hash: hex.EncodeToString(hash[:]), MentorID: subject, ClientID: r.ClientID, ConsentID: id, Resource: u.Resource, RedirectURI: r.RedirectURI, Challenge: r.Challenge, ExpiresAt: now.Add(5 * time.Minute)}
	if record.ExpiresAt.After(consent.ExpiresAt) {
		record.ExpiresAt = consent.ExpiresAt
	}
	if err = u.Store.CreateGrant(ctx, consent, record, now); err != nil {
		return "", err
	}
	// Do not publish a callback if role/approval/consent was lost during commit.
	if _, err = u.currentGrant(ctx, subject, r.ClientID, id); err != nil {
		return "", err
	}
	if !record.ExpiresAt.After(u.now()) {
		return "", domain.ErrMCPMentorDenied
	}
	callback, err := url.Parse(r.RedirectURI)
	if err != nil {
		return "", domain.ErrMCPMentorDenied
	}
	query := callback.Query()
	query.Set("code", code)
	query.Set("state", r.State)
	callback.RawQuery = query.Encode()
	return callback.String(), nil
}
func (u *MCPMentorOAuth) currentGrant(ctx context.Context, subject, client, id string) (*domain.MCPMentorConsent, error) {
	if !u.configured() || ctx == nil || ctx.Err() != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	if !validNonZeroCanonicalMCPUUID(subject) || !validNonZeroCanonicalMCPUUID(id) || !validMCPMentorClientID(client) {
		return nil, domain.ErrMCPMentorDenied
	}
	consent, err := u.Store.Consent(ctx, subject, client, u.Resource, id, u.now())
	if err == domain.ErrNotFound {
		return nil, domain.ErrMCPMentorDenied
	}
	if err != nil {
		return nil, err
	}
	if !validMCPMentorConsent(consent, subject, client, id, u.Resource, u.now()) {
		return nil, domain.ErrMCPMentorDenied
	}
	if err = u.Authority.Check(ctx, subject); err != nil {
		return nil, err
	}
	// SQL rechecks account, client, consent and scopes after external I/O.
	consent, err = u.Store.Consent(ctx, subject, client, u.Resource, id, u.now())
	if err == domain.ErrNotFound {
		return nil, domain.ErrMCPMentorDenied
	}
	if err != nil {
		return nil, err
	}
	if !validMCPMentorConsent(consent, subject, client, id, u.Resource, u.now()) || ctx.Err() != nil {
		return nil, domain.ErrMCPMentorDenied
	}
	return consent, nil
}
func validMCPMentorConsent(c *domain.MCPMentorConsent, subject, client, id, resource string, now time.Time) bool {
	return c != nil && c.ID == id && c.MentorID == subject && c.ClientID == client && c.Resource == resource && c.ExpiresAt.After(now)
}
func (u *MCPMentorOAuth) Exchange(ctx context.Context, r MCPExternalTokenRequest) (*MCPMentorTokenResponse, error) {
	if !u.configured() || ctx == nil || ctx.Err() != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	if r.GrantType != "authorization_code" || r.Scope != "" || r.ResourceURI != u.Resource || !validMCPAuthorizationCode(r.Code) || !validMCPCodeVerifier(r.Verifier) || !validMCPMentorClientID(r.ClientID) || !validMCPRedirectURI(r.RedirectURI) {
		return nil, domain.ErrMCPMentorDenied
	}
	hash := sha256.Sum256([]byte(r.Code))
	digest := hex.EncodeToString(hash[:])
	code, err := u.Store.ConsumeCode(ctx, digest, r.ClientID, r.RedirectURI, u.Resource, u.now())
	if err != nil {
		return nil, err
	}
	if code == nil || code.Hash != digest || code.ClientID != r.ClientID || code.RedirectURI != r.RedirectURI || code.Resource != u.Resource || !code.ExpiresAt.After(u.now()) || VerifyMCPExternalPKCES256(r.Verifier, code.Challenge) != nil {
		return nil, domain.ErrMCPMentorDenied
	}
	consent, err := u.currentGrant(ctx, code.MentorID, code.ClientID, code.ConsentID)
	if err != nil {
		return nil, err
	}
	now := u.now()
	expiry := now.Add(u.AccessTTL)
	if expiry.After(consent.ExpiresAt) {
		expiry = consent.ExpiresAt
	}
	jti, err := GenerateJTI()
	if err != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	claims := MCPMentorAccessClaims{Issuer: u.Tokens.issuer, Subject: code.MentorID, Audience: u.Resource, ClientID: code.ClientID, GrantID: code.ConsentID, Scope: domain.MCPMentorScope, Persona: domain.MCPMentorPersona, IssuedAt: now.Unix(), ExpiresAt: expiry.Unix(), JWTID: jti}
	token, err := u.Tokens.SignAccess(claims)
	if err != nil || ctx.Err() != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	remaining := claims.ExpiresAt - u.now().Unix()
	if remaining <= 0 {
		return nil, domain.ErrMCPMentorDenied
	}
	return &MCPMentorTokenResponse{AccessToken: token, TokenType: "Bearer", ExpiresIn: remaining, Scope: domain.MCPMentorScope}, nil
}

// Verify is called for EVERY protected MCP request. It never accepts Student
// tokens, frontend sessions, historical role claims or cached grant decisions.
func (u *MCPMentorOAuth) Verify(ctx context.Context, raw, resource string, _ time.Time) (*MCPMentorVerifiedGrant, error) {
	if !u.configured() || resource != u.Resource {
		return nil, domain.ErrMCPMentorDenied
	}
	claims, err := u.Tokens.VerifyAccess(raw, resource)
	if err != nil {
		return nil, err
	}
	consent, err := u.currentGrant(ctx, claims.Subject, claims.ClientID, claims.GrantID)
	if err != nil {
		return nil, err
	}
	claims.ExpiresAt = min(claims.ExpiresAt, consent.ExpiresAt.Unix())
	proof, err := u.Tokens.ProfileProof(*claims)
	if err != nil || ctx.Err() != nil || claims.ExpiresAt <= u.now().Unix() {
		return nil, domain.ErrMCPMentorDenied
	}
	return &MCPMentorVerifiedGrant{Persona: domain.MCPMentorPersona, MentorID: claims.Subject, ClientID: claims.ClientID, GrantID: claims.GrantID, Audience: resource, Scopes: []string{domain.MCPMentorScope}, ExpiresAt: claims.ExpiresAt, OwnerProof: proof}, nil
}
func (u *MCPMentorOAuth) Revoke(ctx context.Context, subject, client, resource string) error {
	if !u.configured() || ctx == nil || ctx.Err() != nil {
		return domain.ErrMCPMentorUnavailable
	}
	if !validNonZeroCanonicalMCPUUID(subject) || !validMCPMentorClientID(client) || resource != u.Resource {
		return domain.ErrMCPMentorDenied
	}
	// A live web session may revoke its own grant even after Mentor suspension.
	return u.Store.Revoke(ctx, subject, client, resource)
}
