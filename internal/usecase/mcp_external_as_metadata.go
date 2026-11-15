package usecase

import (
	"net/url"
	"path"
	"strings"
)

// MCPExternalASMetadataConfig is a proposed, source-only authorization-server
// discovery contract. Nothing invokes it from the Auth HTTP router. The caller
// must not set PublicationApproved or mount discovery until the issuer, URLs,
// scope vocabulary, client-registration policy, consent and token endpoint
// implementation have passed the separate owner/runtime acceptance gate.
type MCPExternalASMetadataConfig struct {
	PublicationApproved    bool
	Issuer                 string
	AuthorizationEndpoint  string
	TokenEndpoint          string
	SupportedStudentScopes []string
}

// MCPExternalASMetadata intentionally describes only the candidate public
// authorization-code flow. No dynamic registration, refresh, revocation, JWKS,
// introspection or Client ID Metadata Document support is implied by this type.
type MCPExternalASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
}

// BuildMCPExternalASMetadata validates a prospective RFC 8414 issuer and
// returns its exact well-known path and immutable JSON model. This function
// does not install an HTTP handler, issue codes or tokens, or prove that the
// advertised endpoints exist. Deployment must require a separate readiness
// check of actual authorization and token endpoint implementation.
func BuildMCPExternalASMetadata(cfg MCPExternalASMetadataConfig) (*MCPExternalASMetadata, string, error) {
	if !cfg.PublicationApproved {
		return nil, "", ErrMCPExternalDenied
	}
	issuer, ok := parseMCPExternalASHTTPSURL(cfg.Issuer, false)
	if !ok {
		return nil, "", ErrMCPExternalDenied
	}
	authorization, ok := parseMCPExternalASHTTPSURL(cfg.AuthorizationEndpoint, true)
	if !ok || authorization.Host != issuer.Host {
		return nil, "", ErrMCPExternalDenied
	}
	token, ok := parseMCPExternalASHTTPSURL(cfg.TokenEndpoint, true)
	if !ok || token.Host != issuer.Host || cfg.TokenEndpoint == cfg.AuthorizationEndpoint ||
		cfg.AuthorizationEndpoint == cfg.Issuer || cfg.TokenEndpoint == cfg.Issuer {
		return nil, "", ErrMCPExternalDenied
	}
	if len(cfg.SupportedStudentScopes) == 0 || len(cfg.SupportedStudentScopes) > 32 {
		return nil, "", ErrMCPExternalDenied
	}
	scopes := make([]string, 0, len(cfg.SupportedStudentScopes))
	seen := make(map[string]bool, len(cfg.SupportedStudentScopes))
	for _, scope := range cfg.SupportedStudentScopes {
		if !validMCPScopeToken(scope) || seen[scope] {
			return nil, "", ErrMCPExternalDenied
		}
		seen[scope] = true
		scopes = append(scopes, scope)
	}

	// RFC 8414 section 3: insert the well-known suffix between the host and
	// issuer path; do not simply append it after a pathful issuer.
	discovery := "/.well-known/oauth-authorization-server" + issuer.Path
	if authorization.Path == discovery || token.Path == discovery {
		return nil, "", ErrMCPExternalDenied
	}
	return &MCPExternalASMetadata{
		Issuer:                            cfg.Issuer,
		AuthorizationEndpoint:             cfg.AuthorizationEndpoint,
		TokenEndpoint:                     cfg.TokenEndpoint,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                   scopes,
	}, discovery, nil
}

// parseMCPExternalASHTTPSURL enforces the project's canonical first-party
// issuer/endpoint policy (HTTPS, identical origin and unambiguous ASCII paths).
// RFC 8414 permits more general endpoint hosts, but this external Student
// grant deliberately refuses them until a separately reviewed policy exists.
func parseMCPExternalASHTTPSURL(raw string, endpoint bool) (*url.URL, bool) {
	if raw == "" || strings.ContainsAny(raw, "\\?#") {
		return nil, false
	}
	for _, char := range raw {
		if char < '!' || char > '~' {
			return nil, false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.RawFragment != "" || u.String() != raw ||
		strings.HasSuffix(u.Host, ":") || u.EscapedPath() != u.Path {
		return nil, false
	}
	if u.Path != "" && (u.Path == "/" || !strings.HasPrefix(u.Path, "/") || path.Clean(u.Path) != u.Path) {
		return nil, false
	}
	if endpoint && u.Path == "" {
		return nil, false
	}
	return u, true
}
