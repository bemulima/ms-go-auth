package natsadapter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/example/auth-service/internal/domain"
	nats "github.com/nats-io/nats.go"
)

type mcpMentorRBACClient struct {
	conn permissionNATSRequester
	key  *rsa.PublicKey
	now  func() time.Time
	mu   sync.Mutex
	used map[string]int64
}

func NewMCPMentorRBACClient(conn *nats.Conn, publicPEM string) (domain.MCPMentorRBACClient, error) {
	key, err := parseReviewerPermissionDecisionPublicKey(publicPEM)
	if conn == nil || err != nil || key == nil || key.N.BitLen() < 2048 {
		return nil, domain.ErrMCPMentorUnavailable
	}
	return &mcpMentorRBACClient{conn: conn, key: key, now: time.Now, used: map[string]int64{}}, nil
}

type mcpMentorDecisionClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	Persona       string `json:"persona"`
	Purpose       string `json:"purpose"`
	Scope         string `json:"scope"`
	JWTID         string `json:"jti"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	Active        bool   `json:"active"`
	Allowed       bool   `json:"allowed"`
	RequestJWTID  string `json:"request_jti"`
	RequestDigest string `json:"request_digest"`
}

func (c *mcpMentorRBACClient) CheckMCPMentorAccess(ctx context.Context, proof, subject, nonce string) (bool, error) {
	if c == nil || c.conn == nil || c.key == nil || c.now == nil || ctx == nil || ctx.Err() != nil || len(proof) == 0 || len(proof) > 8192 || !validNonZeroCanonicalReviewerUUID(subject) || !validNonZeroCanonicalReviewerUUID(nonce) {
		return false, domain.ErrMCPMentorUnavailable
	}
	proofParts := strings.Split(proof, ".")
	if len(proofParts) != 3 {
		return false, domain.ErrMCPMentorUnavailable
	}
	requestClaims, err := decodeCanonicalJWTPart(proofParts[1])
	if err != nil {
		return false, domain.ErrMCPMentorUnavailable
	}
	var request struct {
		Issuer    string `json:"iss"`
		Audience  string `json:"aud"`
		Subject   string `json:"sub"`
		Persona   string `json:"persona"`
		Purpose   string `json:"purpose"`
		Scope     string `json:"scope"`
		JWTID     string `json:"jti"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}
	if !utf8.Valid(requestClaims) || mcpMentorDecisionJSON(requestClaims, []string{"iss", "aud", "sub", "persona", "purpose", "scope", "jti", "iat", "exp"}, &request) != nil || request.Audience != domain.MCPMentorRBACAudience || request.Purpose != domain.MCPMentorRBACPurpose || request.Persona != domain.MCPMentorPersona || !domain.ValidMCPMentorScope(request.Scope) || request.Subject != subject || request.JWTID != nonce {
		return false, domain.ErrMCPMentorUnavailable
	}
	data, _ := json.Marshal(struct {
		Proof string `json:"proof"`
	}{proof})
	bound, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	msg, err := c.conn.RequestWithContext(bound, domain.MCPMentorRBACSubject, data)
	if err != nil || msg == nil || len(msg.Data) == 0 || len(msg.Data) > 9<<10 || !utf8.Valid(msg.Data) || bound.Err() != nil {
		return false, domain.ErrMCPMentorUnavailable
	}
	var response struct {
		DecisionJWT string `json:"decision_jwt"`
	}
	if mcpMentorDecisionJSON(msg.Data, []string{"decision_jwt"}, &response) != nil || len(response.DecisionJWT) > 8192 {
		return false, domain.ErrMCPMentorUnavailable
	}
	parts := strings.Split(response.DecisionJWT, ".")
	if len(parts) != 3 {
		return false, domain.ErrMCPMentorUnavailable
	}
	header, e1 := decodeCanonicalJWTPart(parts[0])
	claims, e2 := decodeCanonicalJWTPart(parts[1])
	sig, e3 := decodeCanonicalJWTPart(parts[2])
	var h reviewerPermissionDecisionJWTHeader
	var d mcpMentorDecisionClaims
	if e1 != nil || e2 != nil || e3 != nil || !utf8.Valid(header) || !utf8.Valid(claims) || mcpMentorDecisionJSON(header, []string{"alg", "typ"}, &h) != nil || h.Algorithm != "RS256" || h.Type != "JWT" || mcpMentorDecisionJSON(claims, []string{"iss", "aud", "sub", "persona", "purpose", "scope", "jti", "iat", "exp", "active", "allowed", "request_jti", "request_digest"}, &d) != nil {
		return false, domain.ErrMCPMentorUnavailable
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	binding := sha256.Sum256([]byte(proof))
	if len(sig) != c.key.Size() || rsa.VerifyPKCS1v15(c.key, crypto.SHA256, hash[:], sig) != nil {
		return false, domain.ErrMCPMentorUnavailable
	}
	now := c.now().UTC().Unix()
	if d.Issuer != "ms-go-rbac" || d.Audience != domain.MCPMentorDecisionAudience || d.Persona != domain.MCPMentorPersona || d.Purpose != domain.MCPMentorDecisionPurpose || d.Scope != request.Scope || d.Subject != subject || d.RequestJWTID != nonce || d.RequestDigest != hex.EncodeToString(binding[:]) || !validNonZeroCanonicalReviewerUUID(d.JWTID) || (d.Allowed && !d.Active) || d.IssuedAt <= 0 || d.IssuedAt > now || d.IssuedAt < request.IssuedAt || d.ExpiresAt <= now || d.ExpiresAt > request.ExpiresAt || d.ExpiresAt-d.IssuedAt > 15 || d.ExpiresAt > 1<<53-1 || bound.Err() != nil {
		return false, domain.ErrMCPMentorUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, exp := range c.used {
		if exp <= now {
			delete(c.used, key)
		}
	}
	if _, seen := c.used[d.JWTID]; seen || len(c.used) >= 4096 {
		return false, domain.ErrMCPMentorUnavailable
	}
	c.used[d.JWTID] = d.ExpiresAt
	return d.Active && d.Allowed, nil
}

func mcpMentorDecisionJSON(data []byte, fields []string, target any) error {
	if !utf8.Valid(data) || strictReviewerDecisionJSON(data, fields, target) != nil {
		return domain.ErrMCPMentorUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(data))
	_, _ = d.Token()
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || string(bytes.TrimLeft(data[start:d.InputOffset()], ", \t\r\n")) != "\""+key+"\"" {
			return domain.ErrMCPMentorUnavailable
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return domain.ErrMCPMentorUnavailable
		}
	}
	return nil
}
