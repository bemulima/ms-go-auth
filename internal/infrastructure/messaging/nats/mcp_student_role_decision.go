package natsadapter

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/example/auth-service/internal/domain"
)

const maxMCPStudentRoleDecisionJWTBytes = 16 << 10

// A separate verifier and replay registry prevent reviewer responses from
// becoming MCP role authorization (or vice versa).
type mcpStudentRoleDecisionVerifier struct {
	publicKey *rsa.PublicKey
	now       func() time.Time
	mu        sync.Mutex
	usedJTIs  map[string]time.Time
}

func newMCPStudentRoleDecisionVerifier(encoded string) (*mcpStudentRoleDecisionVerifier, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, nil
	}
	key, err := parseReviewerPermissionDecisionPublicKey(encoded)
	if err != nil {
		return nil, errors.New("invalid MCP Student RBAC decision public key")
	}
	return &mcpStudentRoleDecisionVerifier{publicKey: key, now: time.Now, usedJTIs: make(map[string]time.Time)}, nil
}

type mcpStudentRoleDecisionClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	Type          string `json:"typ"`
	Purpose       string `json:"purpose"`
	Role          string `json:"role"`
	Decision      string `json:"decision"`
	JWTID         string `json:"jti"`
	RequestJWTID  string `json:"request_jti"`
	RequestDigest string `json:"request_digest"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

func (verifier *mcpStudentRoleDecisionVerifier) verify(token, rawProof, expectedSubject, expectedRequestJTI string) (bool, error) {
	if verifier == nil || verifier.publicKey == nil || len(token) == 0 ||
		len(token) > maxMCPStudentRoleDecisionJWTBytes || rawProof == "" ||
		!validNonZeroCanonicalReviewerUUID(expectedSubject) ||
		!validNonZeroCanonicalReviewerUUID(expectedRequestJTI) {
		return false, errors.New("MCP Student role decision invalid")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false, errors.New("MCP Student role decision invalid")
	}
	headerBytes, err := decodeCanonicalJWTPart(parts[0])
	if err != nil {
		return false, errors.New("MCP Student role decision invalid")
	}
	var header reviewerPermissionDecisionJWTHeader
	if strictReviewerDecisionJSON(headerBytes, []string{"alg", "typ"}, &header) != nil ||
		header.Algorithm != "RS256" || header.Type != "JWT" {
		return false, errors.New("MCP Student role decision header invalid")
	}
	claimsBytes, err := decodeCanonicalJWTPart(parts[1])
	if err != nil {
		return false, errors.New("MCP Student role decision invalid")
	}
	var claims mcpStudentRoleDecisionClaims
	claimFields := []string{"iss", "aud", "sub", "typ", "purpose", "role", "decision", "jti", "request_jti", "request_digest", "iat", "exp"}
	if strictReviewerDecisionJSON(claimsBytes, claimFields, &claims) != nil {
		return false, errors.New("MCP Student role decision claims invalid")
	}
	signature, err := decodeCanonicalJWTPart(parts[2])
	if err != nil || len(signature) != verifier.publicKey.Size() {
		return false, errors.New("MCP Student role decision signature invalid")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(verifier.publicKey, crypto.SHA256, digest[:], signature) != nil {
		return false, errors.New("MCP Student role decision signature invalid")
	}
	requestDigest := sha256.Sum256([]byte(rawProof))
	if claims.Issuer != domain.MCPStudentRoleDecisionIssuer ||
		claims.Audience != domain.MCPStudentRoleDecisionAudience ||
		claims.Type != domain.MCPStudentRoleDecisionType ||
		claims.Purpose != domain.MCPStudentRoleDecisionPurpose ||
		claims.Role != domain.MCPStudentRole || claims.Subject != expectedSubject ||
		claims.RequestJWTID != expectedRequestJTI ||
		claims.RequestDigest != hex.EncodeToString(requestDigest[:]) ||
		!validNonZeroCanonicalReviewerUUID(claims.JWTID) ||
		(claims.Decision != "ALLOW" && claims.Decision != "DENY") {
		return false, errors.New("MCP Student role decision binding mismatch")
	}
	nowFn := verifier.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC().Unix()
	if claims.IssuedAt <= 0 ||
		claims.IssuedAt > now+domain.MCPStudentRoleDecisionFutureSkewSecs ||
		claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > domain.MCPStudentRoleDecisionMaxAgeSeconds {
		return false, errors.New("MCP Student role decision expired or outside lifetime")
	}
	if verifier.consumeResponseJTI(claims.JWTID, time.Unix(claims.ExpiresAt, 0)) {
		return false, errors.New("MCP Student role decision replayed")
	}
	return claims.Decision == "ALLOW", nil
}

func (verifier *mcpStudentRoleDecisionVerifier) consumeResponseJTI(jti string, expiresAt time.Time) bool {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	nowFn := verifier.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn()
	for seen, expiry := range verifier.usedJTIs {
		if !expiry.After(now) {
			delete(verifier.usedJTIs, seen)
		}
	}
	if _, exists := verifier.usedJTIs[jti]; exists {
		return true
	}
	verifier.usedJTIs[jti] = expiresAt
	return false
}
