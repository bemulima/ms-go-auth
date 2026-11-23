package usecase

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

var ErrMCPStudentRoleProofUnavailable = errors.New("MCP Student role proof authority unavailable")

// MCPStudentRoleProofSigner is a dormant, role-only Auth-to-RBAC assertion
// signer. The caller must first verify the student from Auth-owned persistence;
// this signer is not an identity lookup or an OAuth token issuer.
type MCPStudentRoleProofSigner struct {
	issuer string
	key    *rsa.PrivateKey
	clock  func() time.Time
}

// NewMCPStudentRoleProofSigner uses the existing Auth JWT RS256 key pair but a
// separate audience and purpose. Missing keys leave the adapter disabled.
// A partially configured or mismatched key pair fails closed.
func NewMCPStudentRoleProofSigner(issuer, privateKeyPEM, publicKeyPEM string) (*MCPStudentRoleProofSigner, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, ErrMCPStudentRoleProofUnavailable
	}
	if strings.TrimSpace(privateKeyPEM) == "" && strings.TrimSpace(publicKeyPEM) == "" {
		return nil, nil
	}
	if strings.TrimSpace(privateKeyPEM) == "" || strings.TrimSpace(publicKeyPEM) == "" {
		return nil, ErrMCPStudentRoleProofUnavailable
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil || key.N.BitLen() < 2048 {
		return nil, ErrMCPStudentRoleProofUnavailable
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPEM))
	if err != nil || publicKey.N.Cmp(key.N) != 0 || publicKey.E != key.E {
		return nil, ErrMCPStudentRoleProofUnavailable
	}
	return &MCPStudentRoleProofSigner{issuer: issuer, key: key, clock: time.Now}, nil
}

// Sign returns a short-lived RS256 RBAC lookup proof and its fresh request JTI.
// The role claim expresses the requested check, not RBAC authorization.
func (signer *MCPStudentRoleProofSigner) Sign(ctx context.Context, verifiedStudentID string) (string, string, error) {
	if signer == nil || signer.key == nil || signer.clock == nil || ctx == nil || ctx.Err() != nil ||
		!canonicalReviewerUUID(verifiedStudentID) {
		return "", "", ErrMCPStudentRoleProofUnavailable
	}
	jti, err := GenerateJTI()
	if err != nil {
		return "", "", ErrMCPStudentRoleProofUnavailable
	}
	now := signer.clock().UTC().Truncate(time.Second)
	if now.Unix() <= 0 || ctx.Err() != nil {
		return "", "", ErrMCPStudentRoleProofUnavailable
	}
	claims := jwt.MapClaims{
		"iss": signer.issuer, "aud": domain.MCPStudentRoleProofAudience,
		"sub": verifiedStudentID, "typ": domain.MCPStudentRoleProofType,
		"purpose": domain.MCPStudentRoleProofPurpose, "role": domain.MCPStudentRole,
		"jti": jti, "iat": now.Unix(),
		"exp": now.Add(domain.MCPStudentRoleProofTTLSeconds * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "JWT"
	signed, err := token.SignedString(signer.key)
	if err != nil || ctx.Err() != nil {
		return "", "", ErrMCPStudentRoleProofUnavailable
	}
	return signed, jti, nil
}
