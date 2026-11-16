package natsadapter

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/example/auth-service/internal/domain"
)

const maxMCPStudentScopeDecisionJWTBytes = 16 << 10

// Deliberately distinct from reviewer and role-only decision verifiers: an
// otherwise valid signed ALLOW for a Student role never authorizes scopes.
type mcpStudentScopeDecisionVerifier struct {
	publicKey *rsa.PublicKey
	now       func() time.Time
	mu        sync.Mutex
	usedJTIs  map[string]time.Time
}

func newMCPStudentScopeDecisionVerifier(encoded string) (*mcpStudentScopeDecisionVerifier, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, nil
	}
	key, err := parseReviewerPermissionDecisionPublicKey(encoded)
	if err != nil {
		return nil, errors.New("invalid MCP Student scopes RBAC decision public key")
	}
	return &mcpStudentScopeDecisionVerifier{publicKey: key, now: time.Now, usedJTIs: make(map[string]time.Time)}, nil
}

type mcpStudentScopeDecisionClaims struct {
	Issuer          string   `json:"iss"`
	Audience        string   `json:"aud"`
	Subject         string   `json:"sub"`
	Type            string   `json:"typ"`
	Purpose         string   `json:"purpose"`
	RequestedScopes []string `json:"requested_scopes"`
	AllowedScopes   []string `json:"allowed_scopes"`
	JWTID           string   `json:"jti"`
	RequestJWTID    string   `json:"request_jti"`
	RequestDigest   string   `json:"request_digest"`
	IssuedAt        int64    `json:"iat"`
	ExpiresAt       int64    `json:"exp"`
}

func (verifier *mcpStudentScopeDecisionVerifier) verify(
	token, rawProof, expectedSubject, expectedRequestJTI string, expectedRequested []string,
) ([]string, error) {
	if verifier == nil || verifier.publicKey == nil || token == "" ||
		len(token) > maxMCPStudentScopeDecisionJWTBytes || rawProof == "" ||
		len(rawProof) > maxMCPStudentScopeProofJWTBytes ||
		!validNonZeroCanonicalReviewerUUID(expectedSubject) ||
		!validNonZeroCanonicalReviewerUUID(expectedRequestJTI) ||
		!domain.ValidMCPStudentRequestedScopes(expectedRequested) {
		return nil, errors.New("MCP Student scopes decision invalid")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errors.New("MCP Student scopes decision invalid")
	}
	headerBytes, err := decodeCanonicalJWTPart(parts[0])
	if err != nil {
		return nil, errors.New("MCP Student scopes decision header invalid")
	}
	var header reviewerPermissionDecisionJWTHeader
	if strictReviewerDecisionJSON(headerBytes, []string{"alg", "typ"}, &header) != nil ||
		header.Algorithm != "RS256" || header.Type != "JWT" {
		return nil, errors.New("MCP Student scopes decision header invalid")
	}
	claimsBytes, err := decodeCanonicalJWTPart(parts[1])
	if err != nil {
		return nil, errors.New("MCP Student scopes decision claims invalid")
	}
	var claims mcpStudentScopeDecisionClaims
	fields := []string{
		"iss", "aud", "sub", "typ", "purpose", "requested_scopes", "allowed_scopes",
		"jti", "request_jti", "request_digest", "iat", "exp",
	}
	if strictReviewerDecisionJSON(claimsBytes, fields, &claims) != nil {
		return nil, errors.New("MCP Student scopes decision claims invalid")
	}
	signature, err := decodeCanonicalJWTPart(parts[2])
	if err != nil || len(signature) != verifier.publicKey.Size() {
		return nil, errors.New("MCP Student scopes decision signature invalid")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(verifier.publicKey, crypto.SHA256, digest[:], signature) != nil {
		return nil, errors.New("MCP Student scopes decision signature invalid")
	}
	proofDigest := sha256.Sum256([]byte(rawProof))
	if claims.Issuer != domain.MCPStudentScopeDecisionIssuer ||
		claims.Audience != domain.MCPStudentScopeDecisionAudience ||
		claims.Type != domain.MCPStudentScopeDecisionType ||
		claims.Purpose != domain.MCPStudentScopeDecisionPurpose ||
		claims.Subject != expectedSubject || claims.RequestJWTID != expectedRequestJTI ||
		claims.RequestDigest != hex.EncodeToString(proofDigest[:]) ||
		!validNonZeroCanonicalReviewerUUID(claims.JWTID) ||
		!slices.Equal(claims.RequestedScopes, expectedRequested) ||
		!domain.ValidMCPStudentAllowedScopes(claims.RequestedScopes, claims.AllowedScopes) {
		return nil, errors.New("MCP Student scopes decision binding mismatch")
	}
	nowFn := verifier.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC().Unix()
	if claims.IssuedAt <= 0 ||
		claims.IssuedAt > now+domain.MCPStudentScopeDecisionFutureSkewSecs ||
		claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > domain.MCPStudentScopeDecisionMaxAgeSeconds {
		return nil, errors.New("MCP Student scopes decision expired or outside lifetime")
	}
	if verifier.consumeResponseJTI(claims.JWTID, time.Unix(claims.ExpiresAt, 0)) {
		return nil, errors.New("MCP Student scopes decision replayed")
	}
	return append([]string{}, claims.AllowedScopes...), nil
}

func (verifier *mcpStudentScopeDecisionVerifier) consumeResponseJTI(jti string, expiry time.Time) bool {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	nowFn := verifier.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn()
	for seen, until := range verifier.usedJTIs {
		if !until.After(now) {
			delete(verifier.usedJTIs, seen)
		}
	}
	if _, exists := verifier.usedJTIs[jti]; exists {
		return true
	}
	verifier.usedJTIs[jti] = expiry
	return false
}
