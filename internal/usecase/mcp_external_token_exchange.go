package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
)

const (
	maxMCPExternalAccessTokenTTL = 5 * time.Minute
	// MCPExternalAccessTokenJOSEType is a requirement for a future JWT signer,
	// applied to the JOSE `typ` HEADER, never as an untrusted JWT body field.
	MCPExternalAccessTokenJOSEType = "at+jwt"
)

// MCPExternalTokenPolicy is a dormant candidate policy; scopes, issuer and
// TTL are not frozen production values. The MCP audience must be an exact,
// distinct HTTPS protected-resource URI; never broaden frontend JWT audience.
type MCPExternalTokenPolicy struct {
	Issuer               string
	ResourceURI          string
	AllowedStudentScopes []string
	AccessTTL            time.Duration
}

// MCPExternalTokenRequest is a normalized FUTURE token endpoint request.
// The HTTP layer must still require POST form-encoding, reject duplicates,
// size-bound inputs and disable secret-bearing query/access logs.
type MCPExternalTokenRequest struct {
	GrantType   string
	Code        string
	Verifier    string
	ClientID    string
	RedirectURI string
	ResourceURI string
	Scope       string // Any supplied scope is denied; token exchange cannot expand the grant.
}

// MCPExternalAccessTokenIntent is a sanitized signing INPUT, not a JWT or an
// access token. A future signer must enforce RS256/keys, typ=at+jwt, issuer,
// audience, TTL, revocation persistence and the resource-server verifier.
// The receipt's raw code, verifier and hash never appear in this payload.
type MCPExternalAccessTokenIntent struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ClientID  string `json:"client_id"`
	GrantID   string `json:"grant_id"`
	Scope     string `json:"scope"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti"`
}

// MCPExternalTokenExchangeUsecase is deliberately not instantiated at startup
// or mounted on any Auth HTTP route. The sole Prepare entrypoint consumes a
// one-use code before obtaining a FRESH trusted grant+RBAC readback. There is
// no standalone intent builder accepting a forged/unused code receipt.
type MCPExternalTokenExchangeUsecase struct {
	Codes  domain.MCPExternalCodeRepository
	Grants domain.MCPExternalTokenGrantReadback
	Policy MCPExternalTokenPolicy
}

// Prepare only returns a claim-intent after successful code redemption AND
// fresh Auth/RBAC rechecks. It cannot issue a token. Any failure, including
// failed readback after code burn, is a uniform denial; reauthorization is
// necessary after a consumed-code failure.
func (u MCPExternalTokenExchangeUsecase) Prepare(
	ctx context.Context, request MCPExternalTokenRequest, now time.Time,
) (*MCPExternalAccessTokenIntent, error) {
	if ctx == nil || ctx.Err() != nil || u.Codes == nil || u.Grants == nil ||
		now.IsZero() || u.Policy.AccessTTL <= 0 ||
		u.Policy.AccessTTL > maxMCPExternalAccessTokenTTL ||
		request.GrantType != "authorization_code" || request.Scope != "" ||
		!validMCPResourceURI(u.Policy.ResourceURI) ||
		request.ResourceURI != u.Policy.ResourceURI ||
		!validMCPExternalTokenPolicy(u.Policy) {
		return nil, ErrMCPExternalDenied
	}

	// Redeem includes the atomic database consume, exact client/redirect/resource
	// binding and S256 check. An invalid-but-well-formed verifier burns the code.
	receipt, err := (MCPExternalCodeUsecase{Codes: u.Codes}).Redeem(
		ctx, request.Code, request.Verifier, request.ClientID,
		request.RedirectURI, request.ResourceURI, now,
	)
	if err != nil || receipt == nil {
		return nil, ErrMCPExternalDenied
	}

	status, err := u.Grants.ReadbackMCPExternalTokenGrant(
		ctx, receipt.StudentID, receipt.ClientID, receipt.ConsentID,
		receipt.ResourceURI, now.UTC(),
	)
	if err != nil || ctx.Err() != nil || status == nil ||
		!status.StudentActive || !status.ClientActive || !status.ConsentActive ||
		!status.RBACStudentActive ||
		status.StudentID != receipt.StudentID ||
		status.ClientID != receipt.ClientID ||
		status.ConsentID != receipt.ConsentID ||
		status.ResourceURI != receipt.ResourceURI ||
		!status.ConsentExpiresAt.After(now) {
		return nil, ErrMCPExternalDenied
	}
	for _, scope := range receipt.Scopes {
		if !hasMCPExactScope(u.Policy.AllowedStudentScopes, scope) ||
			!hasMCPExactScope(status.ClientScopes, scope) ||
			!hasMCPExactScope(status.ConsentScopes, scope) ||
			!hasMCPExactScope(status.RBACStudentScopes, scope) {
			return nil, ErrMCPExternalDenied
		}
	}

	expiry := now.Add(u.Policy.AccessTTL)
	if status.ConsentExpiresAt.Before(expiry) {
		expiry = status.ConsentExpiresAt
	}
	if expiry.Unix() <= now.Unix() {
		return nil, ErrMCPExternalDenied
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil || ctx.Err() != nil {
		return nil, ErrMCPExternalDenied
	}
	return &MCPExternalAccessTokenIntent{
		Issuer:    u.Policy.Issuer,
		Subject:   receipt.StudentID,
		Audience:  u.Policy.ResourceURI,
		ClientID:  receipt.ClientID,
		GrantID:   receipt.ConsentID,
		Scope:     strings.Join(receipt.Scopes, " "),
		IssuedAt:  now.UTC().Unix(),
		ExpiresAt: expiry.UTC().Unix(),
		JWTID:     base64.RawURLEncoding.EncodeToString(entropy[:]),
	}, nil
}

func validMCPExternalTokenPolicy(policy MCPExternalTokenPolicy) bool {
	if _, ok := parseMCPExternalASHTTPSURL(policy.Issuer, false); !ok ||
		len(policy.AllowedStudentScopes) == 0 || len(policy.AllowedStudentScopes) > 32 {
		return false
	}
	seen := make(map[string]bool, len(policy.AllowedStudentScopes))
	for _, scope := range policy.AllowedStudentScopes {
		if !validMCPScopeToken(scope) || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return true
}
