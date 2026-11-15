package usecase

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"
)

// ErrMCPExternalDenied is deliberately uniform: rejected client, scope, grant,
// or PKCE inputs must never disclose which credential or identifier matched.
var ErrMCPExternalDenied = errors.New("external MCP OAuth request denied")

// MCPExternalAuthorizationRequest contains untrusted third-party OAuth inputs.
// No field in this value establishes the currently authenticated Student.
type MCPExternalAuthorizationRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	ResourceURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
}

// MCPExternalClient must be resolved and verified through an Auth-owned client
// registry or an approved Client ID Metadata Document verifier, not client JSON.
type MCPExternalClient struct {
	ID            string
	RedirectURIs  []string
	AllowedScopes []string
}

// MCPExternalConsent must be fetched by Auth for the verified Student; it is
// not a field supplied by the external client or an LLM prompt.
type MCPExternalConsent struct {
	// ID is an Auth-persisted consent row key, never a client-supplied value.
	ID          string
	StudentID   string
	ClientID    string
	ResourceURI string
	Scopes      []string
	ExpiresAt   time.Time
	Revoked     bool
}

type MCPExternalPolicy struct {
	ResourceURI          string
	AllowedStudentScopes []string
}

// ValidateMCPExternalAuthorization is the pure authorization-completion gate
// before creating a one-use code. The caller must independently authenticate
// Student, verify client registration, obtain persisted consent, validate CSRF,
// and perform a current RBAC check. This function never issues a code/token.
func ValidateMCPExternalAuthorization(
	policy MCPExternalPolicy,
	request MCPExternalAuthorizationRequest,
	client MCPExternalClient,
	consent MCPExternalConsent,
	verifiedStudentID string,
	now time.Time,
) ([]string, error) {
	if verifiedStudentID == "" || !validMCPResourceURI(policy.ResourceURI) ||
		request.ResponseType != "code" ||
		request.ClientID == "" || request.ClientID != client.ID ||
		request.ResourceURI != policy.ResourceURI ||
		request.CodeChallengeMethod != "S256" || !validMCPCodeChallenge(request.CodeChallenge) ||
		!registeredMCPRedirect(request.RedirectURI, client.RedirectURIs) ||
		consent.Revoked || !consent.ExpiresAt.After(now) ||
		consent.StudentID != verifiedStudentID ||
		consent.ClientID != client.ID || consent.ResourceURI != policy.ResourceURI {
		return nil, ErrMCPExternalDenied
	}

	scopes, ok := parseMCPRequestedScopes(request.Scope)
	if !ok {
		return nil, ErrMCPExternalDenied
	}
	for _, scope := range scopes {
		if !hasMCPExactScope(client.AllowedScopes, scope) ||
			!hasMCPExactScope(policy.AllowedStudentScopes, scope) ||
			!hasMCPExactScope(consent.Scopes, scope) {
			return nil, ErrMCPExternalDenied
		}
	}
	return scopes, nil
}

// VerifyMCPExternalPKCES256 is the token-exchange gate for a single-use
// authorization code already atomically consumed from an Auth-owned store.
// It must not accept method=plain or reuse CodeVerifier from Google/GitHub login.
func VerifyMCPExternalPKCES256(verifier, challenge string) error {
	if !validMCPCodeVerifier(verifier) || !validMCPCodeChallenge(challenge) {
		return ErrMCPExternalDenied
	}
	hash := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(hash[:])
	if subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) != 1 {
		return ErrMCPExternalDenied
	}
	return nil
}

func validMCPResourceURI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u != nil && u.Scheme == "https" && u.Host != "" &&
		u.User == nil && u.Opaque == "" && u.EscapedPath() == "/mcp" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(raw, "#")
}

func registeredMCPRedirect(raw string, registered []string) bool {
	if !validMCPRedirectURI(raw) {
		return false
	}
	for _, candidate := range registered {
		if raw == candidate { // deliberately exact, no prefix or wildcard matching
			return true
		}
	}
	return false
}

func validMCPRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	if u.Scheme != "https" && !(u.Scheme == "http" &&
		(u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return false
	}
	return true
}

func parseMCPRequestedScopes(raw string) ([]string, bool) {
	if len(raw) == 0 || len(raw) > 4096 || strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, "\r\n\t") || strings.Contains(raw, "  ") {
		return nil, false
	}
	scopes := strings.Split(raw, " ")
	if len(scopes) == 0 || len(scopes) > 32 {
		return nil, false
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if !validMCPScopeToken(scope) || seen[scope] {
			return nil, false
		}
		seen[scope] = true
	}
	return scopes, true
}

func hasMCPExactScope(allowed []string, scope string) bool {
	for _, candidate := range allowed {
		if candidate == scope {
			return true
		}
	}
	return false
}

func validMCPScopeToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, ch := range s {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' || ch == ':' || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func validMCPCodeVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' || ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			continue
		}
		return false
	}
	return true
}

func validMCPCodeChallenge(value string) bool {
	// S256 produces exactly 32 bytes of SHA-256 encoded to 43 base64url chars.
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}
