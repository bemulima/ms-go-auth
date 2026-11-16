package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
)

const maxMCPExternalCodeTTL = 5 * time.Minute

// MCPExternalCodeUsecase persists one-use PKCE codes. The separate Auth-owned
// completion and token handlers must provide verified identity, registered
// client/consent state and fresh RBAC scope decisions before using it.
type MCPExternalCodeUsecase struct {
	Codes domain.MCPExternalCodeRepository
	TTL   time.Duration
}

// Issue requires a verified Auth Student subject and an Auth-loaded persisted
// consent (with ID), not an LLM/client assertion. The repository must recheck
// the consent and client against PostgreSQL at the point of insertion.
func (u MCPExternalCodeUsecase) Issue(
	ctx context.Context,
	policy MCPExternalPolicy,
	request MCPExternalAuthorizationRequest,
	client MCPExternalClient,
	consent MCPExternalConsent,
	verifiedStudentID string,
	now time.Time,
) (string, error) {
	if u.Codes == nil || u.TTL <= 0 || u.TTL > maxMCPExternalCodeTTL ||
		consent.ID == "" || now.IsZero() {
		return "", ErrMCPExternalDenied
	}
	scopes, err := ValidateMCPExternalAuthorization(policy, request, client, consent, verifiedStudentID, now)
	if err != nil {
		return "", ErrMCPExternalDenied
	}

	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", ErrMCPExternalDenied
	}
	code := base64.RawURLEncoding.EncodeToString(entropy[:])
	digest := sha256.Sum256([]byte(code))
	expires := now.Add(u.TTL)
	if expires.After(consent.ExpiresAt) {
		expires = consent.ExpiresAt
	}
	if err := u.Codes.CreateMCPExternalCode(ctx, &domain.MCPExternalAuthorizationCode{
		CodeHash:      hex.EncodeToString(digest[:]),
		StudentID:     verifiedStudentID,
		ClientID:      client.ID,
		ConsentID:     consent.ID,
		RedirectURI:   request.RedirectURI,
		ResourceURI:   policy.ResourceURI,
		CodeChallenge: request.CodeChallenge,
		Scopes:        append([]string(nil), scopes...),
		ExpiresAt:     expires.UTC(),
	}); err != nil {
		return "", ErrMCPExternalDenied
	}
	return code, nil
}

// Redeem atomically burns a code before PKCE checking. A valid-shape but wrong
// verifier deliberately consumes the code; retries must reauthorize. This
// returns an internal receipt only, never a token. Before actual token signing,
// Auth must recheck session/RBAC/consent and persist refresh/revocation state.
func (u MCPExternalCodeUsecase) Redeem(
	ctx context.Context,
	code, verifier, clientID, redirectURI, resourceURI string,
	now time.Time,
) (*domain.MCPExternalAuthorizationCode, error) {
	if u.Codes == nil || now.IsZero() || !validMCPAuthorizationCode(code) ||
		!validMCPCodeVerifier(verifier) || clientID == "" ||
		!validMCPRedirectURI(redirectURI) ||
		!validMCPResourceURI(resourceURI) {
		return nil, ErrMCPExternalDenied
	}
	digest := sha256.Sum256([]byte(code))
	record, err := u.Codes.ConsumeMCPExternalCode(ctx, hex.EncodeToString(digest[:]), clientID, redirectURI, resourceURI, now.UTC())
	if err != nil || record == nil || record.CodeHash != hex.EncodeToString(digest[:]) ||
		record.StudentID == "" || record.ConsentID == "" ||
		record.ClientID != clientID || record.RedirectURI != redirectURI ||
		record.ResourceURI != resourceURI || !record.ExpiresAt.After(now) ||
		VerifyMCPExternalPKCES256(verifier, record.CodeChallenge) != nil {
		return nil, ErrMCPExternalDenied
	}
	scopes, ok := parseMCPRequestedScopes(strings.Join(record.Scopes, " "))
	if !ok || len(scopes) != len(record.Scopes) {
		return nil, ErrMCPExternalDenied
	}
	record.Scopes = append([]string(nil), scopes...)
	return record, nil
}

func validMCPAuthorizationCode(code string) bool {
	if len(code) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(code)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == code
}
