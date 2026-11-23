package usecase

import (
	"context"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

var ErrMCPStudentScopeProofUnavailable = errors.New("MCP Student scope proof authority unavailable")

// MCPStudentScopeProofSigner is dormant and must only receive an Auth-owned
// fresh grant snapshot after verified account/client/consent readback.
// A snapshot alone never authorizes token issuance or data access.
type MCPStudentScopeProofSigner struct {
	issuer string
	key    *rsa.PrivateKey
	clock  func() time.Time
}

// The exact existing Auth JWT key pair is required. Missing keys disable the
// producer; partial, weak, or mismatched keys never produce an unsigned proof.
func NewMCPStudentScopeProofSigner(issuer, privateKeyPEM, publicKeyPEM string) (*MCPStudentScopeProofSigner, error) {
	roleSigner, err := NewMCPStudentRoleProofSigner(issuer, privateKeyPEM, publicKeyPEM)
	if err != nil {
		return nil, ErrMCPStudentScopeProofUnavailable
	}
	if roleSigner == nil {
		return nil, nil
	}
	return &MCPStudentScopeProofSigner{issuer: roleSigner.issuer, key: roleSigner.key, clock: time.Now}, nil
}

// Sign requires canonical requested scopes contained in BOTH the persisted
// client allowance and consent, preventing the producer from signing a
// broader request than the fresh Auth grant snapshot permits.
func (signer *MCPStudentScopeProofSigner) Sign(
	ctx context.Context, snapshot *domain.MCPExternalAuthGrantSnapshot, requestedScopes []string,
) (string, string, error) {
	if signer == nil || signer.key == nil || signer.clock == nil ||
		ctx == nil || ctx.Err() != nil || snapshot == nil ||
		!canonicalReviewerUUID(snapshot.StudentID) || !canonicalReviewerUUID(snapshot.ConsentID) ||
		snapshot.ClientID == "" || snapshot.ResourceURI == "" ||
		!domain.ValidMCPStudentRequestedScopes(requestedScopes) ||
		!mcpGrantContainsAllScopes(snapshot.ClientScopes, requestedScopes) ||
		!mcpGrantContainsAllScopes(snapshot.ConsentScopes, requestedScopes) {
		return "", "", ErrMCPStudentScopeProofUnavailable
	}
	now := signer.clock().UTC().Truncate(time.Second)
	if now.Unix() <= 0 || !snapshot.ConsentExpiresAt.After(now) || ctx.Err() != nil {
		return "", "", ErrMCPStudentScopeProofUnavailable
	}
	expiry := now.Add(domain.MCPStudentScopeProofTTLSeconds * time.Second)
	if snapshot.ConsentExpiresAt.Before(expiry) {
		expiry = snapshot.ConsentExpiresAt
	}
	expiresAt := expiry.Unix()
	if expiresAt <= now.Unix() {
		return "", "", ErrMCPStudentScopeProofUnavailable
	}
	jti, err := GenerateJTI()
	if err != nil {
		return "", "", ErrMCPStudentScopeProofUnavailable
	}
	claims := jwt.MapClaims{
		"iss": signer.issuer, "aud": domain.MCPStudentScopeProofAudience,
		"sub": snapshot.StudentID, "typ": domain.MCPStudentScopeProofType,
		"purpose": domain.MCPStudentScopeProofPurpose,
		"scopes":  append([]string(nil), requestedScopes...),
		"jti":     jti, "iat": now.Unix(), "exp": expiresAt,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "JWT"
	proof, err := token.SignedString(signer.key)
	if err != nil || ctx.Err() != nil {
		return "", "", ErrMCPStudentScopeProofUnavailable
	}
	return proof, jti, nil
}

func mcpGrantContainsAllScopes(granted, requested []string) bool {
	for _, scope := range requested {
		found := false
		for _, valid := range granted {
			if valid == scope {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
