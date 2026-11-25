package usecase

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

// MCPMentorTokens uses a dedicated keypair and an exact, distinct JOSE type.
// Cryptographic verification alone never authorizes a Mentor MCP request.
type MCPMentorTokens struct {
	issuer, resource string
	private          *rsa.PrivateKey
	public           *rsa.PublicKey
	now              func() time.Time
}
type MCPMentorAccessClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ClientID  string `json:"client_id"`
	GrantID   string `json:"grant_id"`
	Scope     string `json:"scope"`
	Persona   string `json:"persona"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti"`
}

func NewMCPMentorTokens(issuer, resource, privatePEM, publicPEM string) (*MCPMentorTokens, error) {
	u, err := url.Parse(issuer)
	for _, raw := range []string{issuer, resource} {
		for _, b := range []byte(raw) {
			if b < 33 || b > 126 || b == '\\' {
				return nil, domain.ErrMCPMentorUnavailable
			}
		}
	}
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/mentor" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != issuer || len(issuer) > 2048 || len(resource) > 2048 || !validMCPResourceURI(resource) || len(privatePEM) > 16384 || len(publicPEM) > 16384 {
		return nil, domain.ErrMCPMentorUnavailable
	}
	priv, e1 := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	pub, e2 := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	if e1 != nil || e2 != nil || priv == nil || pub == nil || priv.N.BitLen() < 2048 || priv.N.BitLen() > 8192 || pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		return nil, domain.ErrMCPMentorUnavailable
	}
	return &MCPMentorTokens{issuer: issuer, resource: resource, private: priv, public: pub, now: time.Now}, nil
}
func (a *MCPMentorTokens) SignAccess(c MCPMentorAccessClaims) (string, error) {
	if a == nil || a.private == nil || !a.validAccess(c) {
		return "", domain.ErrMCPMentorDenied
	}
	return a.sign(domain.MCPMentorAccessType, c)
}
func (a *MCPMentorTokens) VerifyAccess(raw, resource string) (*MCPMentorAccessClaims, error) {
	if a == nil || a.public == nil || resource != a.resource || len(raw) == 0 || len(raw) > 8192 {
		return nil, domain.ErrMCPMentorDenied
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, domain.ErrMCPMentorDenied
	}
	h, e1 := mcpMentorPart(parts[0])
	data, e2 := mcpMentorPart(parts[1])
	sig, e3 := mcpMentorPart(parts[2])
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	var c MCPMentorAccessClaims
	if e1 != nil || e2 != nil || e3 != nil || mcpMentorObject(h, []string{"alg", "typ"}, &header) != nil || header.Algorithm != "RS256" || header.Type != domain.MCPMentorAccessType || mcpMentorObject(data, []string{"iss", "sub", "aud", "client_id", "grant_id", "scope", "persona", "iat", "exp", "jti"}, &c) != nil || !a.validAccess(c) {
		return nil, domain.ErrMCPMentorDenied
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != a.public.Size() || rsa.VerifyPKCS1v15(a.public, crypto.SHA256, digest[:], sig) != nil {
		return nil, domain.ErrMCPMentorDenied
	}
	return &c, nil
}
func (a *MCPMentorTokens) validAccess(c MCPMentorAccessClaims) bool {
	if a == nil || a.now == nil {
		return false
	}
	now := a.now().UTC().Unix()
	return c.Issuer == a.issuer && c.Audience == a.resource && c.Persona == domain.MCPMentorPersona && domain.ValidMCPMentorScope(c.Scope) && validNonZeroCanonicalMCPUUID(c.Subject) && validNonZeroCanonicalMCPUUID(c.GrantID) && validNonZeroCanonicalMCPUUID(c.JWTID) && validMCPMentorClientID(c.ClientID) && c.IssuedAt > 0 && c.IssuedAt <= now && c.ExpiresAt > now && c.ExpiresAt-c.IssuedAt <= 300 && c.ExpiresAt <= 1<<53-1
}
func (a *MCPMentorTokens) RBACProof(subject, scope string) (string, string, error) {
	if !domain.ValidMCPMentorScope(scope) {
		return "", "", domain.ErrMCPMentorDenied
	}
	return a.proof(subject, domain.MCPMentorRBACAudience, domain.MCPMentorRBACPurpose, scope, nil)
}
func (a *MCPMentorTokens) ApprovalProof(subject string) (string, error) {
	raw, _, err := a.proof(subject, domain.MCPMentorOwnerAudience, domain.MCPMentorApprovalPurpose, "", nil)
	return raw, err
}
func (a *MCPMentorTokens) ProfileProof(c MCPMentorAccessClaims) (string, error) {
	if c.Scope != domain.MCPMentorScope {
		return "", domain.ErrMCPMentorDenied
	}
	return a.OwnerReadProof(c)
}

func (a *MCPMentorTokens) OwnerReadProof(c MCPMentorAccessClaims) (string, error) {
	if !a.validAccess(c) {
		return "", domain.ErrMCPMentorDenied
	}
	purpose := domain.MCPMentorProfilePurpose
	if c.Scope == domain.MCPMentorOffersScope {
		purpose = domain.MCPMentorOffersPurpose
	} else if domain.IsMCPMentorWorkspaceReadScope(c.Scope) {
		purpose = domain.MCPMentorWorkspaceReadPurpose
	}
	raw, _, err := a.proof(c.Subject, domain.MCPMentorOwnerAudience, purpose, c.Scope, &c)
	return raw, err
}
func (a *MCPMentorTokens) proof(subject, audience, purpose, scope string, grant *MCPMentorAccessClaims) (string, string, error) {
	if a == nil || a.private == nil || a.now == nil || !validNonZeroCanonicalMCPUUID(subject) {
		return "", "", domain.ErrMCPMentorUnavailable
	}
	jti, err := GenerateJTI()
	if err != nil {
		return "", "", domain.ErrMCPMentorUnavailable
	}
	now := a.now().UTC().Unix()
	if now <= 0 {
		return "", "", domain.ErrMCPMentorUnavailable
	}
	claims := map[string]any{"iss": a.issuer, "aud": audience, "sub": subject, "persona": domain.MCPMentorPersona, "purpose": purpose, "iat": now, "exp": now + 15, "jti": jti}
	if purpose == domain.MCPMentorRBACPurpose {
		claims["scope"] = scope
	}
	if grant != nil {
		claims["client_id"], claims["grant_id"], claims["resource"], claims["scope"] = grant.ClientID, grant.GrantID, grant.Audience, grant.Scope
		claims["exp"] = min(now+15, grant.ExpiresAt)
	}
	raw, err := a.sign("JWT", claims)
	return raw, jti, err
}
func (a *MCPMentorTokens) sign(typ string, claims any) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", domain.ErrMCPMentorUnavailable
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": typ})
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.private, crypto.SHA256, digest[:])
	if err != nil {
		return "", domain.ErrMCPMentorUnavailable
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func validMCPMentorClientID(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func mcpMentorPart(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, domain.ErrMCPMentorDenied
	}
	return b, nil
}

// Exact keys, including their lexical spelling; JSON aliases, duplicate keys,
// nulls, invalid UTF-8, unknown fields and trailing values fail closed.
func mcpMentorObject(data []byte, fields []string, target any) error {
	if !utf8.Valid(data) {
		return domain.ErrMCPMentorDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return domain.ErrMCPMentorDenied
	}
	allowed := map[string]bool{}
	for _, k := range fields {
		allowed[k] = true
	}
	seen := map[string]bool{}
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return domain.ErrMCPMentorDenied
		}
		lex := bytes.TrimLeft(data[start:d.InputOffset()], ", \r\n\t")
		if string(lex) != "\""+key+"\"" {
			return domain.ErrMCPMentorDenied
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return domain.ErrMCPMentorDenied
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || len(seen) != len(fields) || d.Decode(new(any)) != io.EOF {
		return domain.ErrMCPMentorDenied
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return domain.ErrMCPMentorDenied
	}
	return nil
}
