package natsadapter

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/example/auth-service/internal/domain"
)

const maxReviewerPermissionDecisionJWTBytes = 16 << 10

type reviewerPermissionDecisionVerifier struct {
	publicKey *rsa.PublicKey
	now       func() time.Time
	mu        sync.Mutex
	usedJTIs  map[string]time.Time
}

func newReviewerPermissionDecisionVerifier(encoded string) (*reviewerPermissionDecisionVerifier, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, nil
	}
	key, err := parseReviewerPermissionDecisionPublicKey(encoded)
	if err != nil {
		return nil, errors.New("AUTH_RBAC_PERMISSION_DECISION_PUBLIC_KEY must be an RSA public key")
	}
	return &reviewerPermissionDecisionVerifier{publicKey: key, now: time.Now, usedJTIs: make(map[string]time.Time)}, nil
}

func parseReviewerPermissionDecisionPublicKey(encoded string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid PEM")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		parsed, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, errors.New("unsupported PEM block type")
	}
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
		return nil, errors.New("invalid RSA public key")
	}
	return key, nil
}

type reviewerPermissionDecisionJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type reviewerPermissionDecisionJWTClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	Type          string `json:"typ"`
	Purpose       string `json:"purpose"`
	Permission    string `json:"permission"`
	Decision      string `json:"decision"`
	JWTID         string `json:"jti"`
	RequestJWTID  string `json:"request_jti"`
	RequestDigest string `json:"request_digest"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

func (verifier *reviewerPermissionDecisionVerifier) verify(token, rawProof, expectedSubject, expectedRequestJTI string) (bool, error) {
	if verifier == nil || verifier.publicKey == nil {
		return false, errors.New("reviewer permission decision authority unavailable")
	}
	if len(token) == 0 || len(token) > maxReviewerPermissionDecisionJWTBytes ||
		!validNonZeroCanonicalReviewerUUID(expectedSubject) || !validNonZeroCanonicalReviewerUUID(expectedRequestJTI) || rawProof == "" {
		return false, errors.New("invalid reviewer permission decision")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false, errors.New("invalid reviewer permission decision")
	}
	headerBytes, err := decodeCanonicalJWTPart(parts[0])
	if err != nil {
		return false, errors.New("invalid reviewer permission decision")
	}
	var header reviewerPermissionDecisionJWTHeader
	if strictReviewerDecisionJSON(headerBytes, []string{"alg", "typ"}, &header) != nil ||
		header.Algorithm != "RS256" || header.Type != "JWT" {
		return false, errors.New("invalid reviewer permission decision header")
	}
	claimsBytes, err := decodeCanonicalJWTPart(parts[1])
	if err != nil {
		return false, errors.New("invalid reviewer permission decision")
	}
	var claims reviewerPermissionDecisionJWTClaims
	claimFields := []string{"iss", "aud", "sub", "typ", "purpose", "permission", "decision", "jti", "request_jti", "request_digest", "iat", "exp"}
	if strictReviewerDecisionJSON(claimsBytes, claimFields, &claims) != nil {
		return false, errors.New("invalid reviewer permission decision claims")
	}
	signature, err := decodeCanonicalJWTPart(parts[2])
	if err != nil || len(signature) != verifier.publicKey.Size() {
		return false, errors.New("invalid reviewer permission decision signature")
	}
	signed := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signed))
	if rsa.VerifyPKCS1v15(verifier.publicKey, crypto.SHA256, digest[:], signature) != nil {
		return false, errors.New("invalid reviewer permission decision signature")
	}
	requestDigest := sha256.Sum256([]byte(rawProof))
	if claims.Issuer != domain.ReviewerPermissionDecisionIssuer ||
		claims.Audience != domain.ReviewerPermissionDecisionAudience ||
		claims.Type != domain.ReviewerPermissionDecisionType ||
		claims.Purpose != domain.ReviewerPermissionDecisionPurpose ||
		claims.Subject != expectedSubject || claims.Permission != domain.KnowledgeGraphReviewPermission ||
		claims.RequestJWTID != expectedRequestJTI || claims.RequestDigest != hex.EncodeToString(requestDigest[:]) ||
		!validNonZeroCanonicalReviewerUUID(claims.JWTID) ||
		(claims.Decision != "ALLOW" && claims.Decision != "DENY") {
		return false, errors.New("reviewer permission decision binding mismatch")
	}
	nowFn := verifier.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now+domain.ReviewerPermissionDecisionFutureSkewSeconds ||
		claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > domain.ReviewerPermissionDecisionMaxAgeSeconds {
		return false, errors.New("reviewer permission decision expired or outside lifetime")
	}
	if verifier.consumeResponseJTI(claims.JWTID, time.Unix(claims.ExpiresAt, 0)) {
		return false, errors.New("reviewer permission decision replayed")
	}
	return claims.Decision == "ALLOW", nil
}

func (verifier *reviewerPermissionDecisionVerifier) consumeResponseJTI(jti string, expiresAt time.Time) bool {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	now := time.Now()
	if verifier.now != nil {
		now = verifier.now()
	}
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

func validNonZeroCanonicalReviewerUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}

func decodeCanonicalJWTPart(part string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != part {
		return nil, errors.New("non-canonical JWT part")
	}
	return decoded, nil
}

func strictReviewerDecisionJSON(data []byte, required []string, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("decision JSON must be an object")
	}
	allowed := make(map[string]struct{}, len(required))
	for _, key := range required {
		allowed[key] = struct{}{}
	}
	seen := make(map[string]struct{}, len(required))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return errors.New("invalid decision JSON key")
		}
		if _, ok := allowed[key]; !ok {
			return errors.New("unknown decision JSON field")
		}
		if _, ok := seen[key]; ok {
			return errors.New("duplicate decision JSON field")
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("invalid decision JSON value")
		}
	}
	if len(seen) != len(required) {
		return errors.New("missing decision JSON field")
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("decision JSON object is not closed")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing decision JSON value")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}
