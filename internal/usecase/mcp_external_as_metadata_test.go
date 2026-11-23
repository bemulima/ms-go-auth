package usecase

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func validMCPExternalASMetadataConfig() MCPExternalASMetadataConfig {
	return MCPExternalASMetadataConfig{
		PublicationApproved:    true,
		Issuer:                 "https://auth.example.test/oauth",
		AuthorizationEndpoint:  "https://auth.example.test/oauth/authorize",
		TokenEndpoint:          "https://auth.example.test/oauth/token",
		SupportedStudentScopes: []string{"courses:read", "lessons:read"},
	}
}

func TestMCPExternalASMetadataCanonicalDiscoveryAndExactJSON(t *testing.T) {
	config := validMCPExternalASMetadataConfig()
	metadata, discoveryPath, err := BuildMCPExternalASMetadata(config)
	if err != nil {
		t.Fatalf("valid dormant metadata rejected: %v", err)
	}
	if discoveryPath != "/.well-known/oauth-authorization-server/oauth" {
		t.Fatalf("discovery path=%q", discoveryPath)
	}
	if metadata.Issuer != config.Issuer ||
		metadata.AuthorizationEndpoint != config.AuthorizationEndpoint ||
		metadata.TokenEndpoint != config.TokenEndpoint {
		t.Fatalf("metadata endpoint identity mismatch: %+v", metadata)
	}
	if !reflect.DeepEqual(metadata.ResponseTypesSupported, []string{"code"}) ||
		!reflect.DeepEqual(metadata.GrantTypesSupported, []string{"authorization_code"}) ||
		!reflect.DeepEqual(metadata.CodeChallengeMethodsSupported, []string{"S256"}) ||
		!reflect.DeepEqual(metadata.TokenEndpointAuthMethodsSupported, []string{"none"}) ||
		!reflect.DeepEqual(metadata.ScopesSupported, config.SupportedStudentScopes) {
		t.Fatalf("unsupported protocol feature advertised: %+v", metadata)
	}

	// Keep both the producer and the JSON contract free from token, dynamic
	// registration, refresh, revocation or signing-key claims not implemented.
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"registration_endpoint", "revocation_endpoint", "jwks_uri",
		"introspection_endpoint", "client_id_metadata_document_supported",
	} {
		if _, ok := body[forbidden]; ok {
			t.Fatalf("unimplemented feature %s advertised: %s", forbidden, encoded)
		}
	}
	if len(body) != 8 {
		t.Fatalf("metadata fields=%d, want precisely 8: %s", len(body), encoded)
	}
	if strings.Contains(string(encoded), "refresh_token") || strings.Contains(string(encoded), "plain") {
		t.Fatalf("unsupported grant/PKCE method: %s", encoded)
	}

	// The returned metadata must not be mutated through the source config.
	config.SupportedStudentScopes[0] = "tampered"
	if metadata.ScopesSupported[0] != "courses:read" {
		t.Fatalf("metadata aliases mutable config: %q", metadata.ScopesSupported)
	}
}

func TestMCPExternalASMetadataIssuerWithoutPath(t *testing.T) {
	config := validMCPExternalASMetadataConfig()
	config.Issuer = "https://auth.example.test"
	metadata, discoveryPath, err := BuildMCPExternalASMetadata(config)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Issuer != config.Issuer || discoveryPath != "/.well-known/oauth-authorization-server" {
		t.Fatalf("root issuer=%q discovery=%q", metadata.Issuer, discoveryPath)
	}
}

func TestMCPExternalASMetadataFailClosedMatrix(t *testing.T) {
	tests := []struct {
		name   string
		change func(*MCPExternalASMetadataConfig)
	}{
		{"disabled", func(c *MCPExternalASMetadataConfig) { c.PublicationApproved = false }},
		{"missing-issuer", func(c *MCPExternalASMetadataConfig) { c.Issuer = "" }},
		{"http-issuer", func(c *MCPExternalASMetadataConfig) { c.Issuer = "http://auth.example.test" }},
		{"issuer-userinfo", func(c *MCPExternalASMetadataConfig) { c.Issuer = "https://victim@auth.example.test" }},
		{"issuer-query", func(c *MCPExternalASMetadataConfig) { c.Issuer += "?tracking=1" }},
		{"issuer-empty-query", func(c *MCPExternalASMetadataConfig) { c.Issuer += "?" }},
		{"issuer-fragment", func(c *MCPExternalASMetadataConfig) { c.Issuer += "#frag" }},
		{"issuer-empty-fragment", func(c *MCPExternalASMetadataConfig) { c.Issuer += "#" }},
		{"issuer-dot-segments", func(c *MCPExternalASMetadataConfig) { c.Issuer += "/../other" }},
		{"issuer-double-slash", func(c *MCPExternalASMetadataConfig) { c.Issuer += "//other" }},
		{"issuer-encoded-slash", func(c *MCPExternalASMetadataConfig) { c.Issuer += "%2fother" }},
		{"issuer-trailing-slash", func(c *MCPExternalASMetadataConfig) { c.Issuer += "/" }},
		{"issuer-no-host", func(c *MCPExternalASMetadataConfig) { c.Issuer = "https:///oauth" }},
		{"issuer-non-http-scheme", func(c *MCPExternalASMetadataConfig) { c.Issuer = "javascript:alert(1)" }},
		{"issuer-whitespace", func(c *MCPExternalASMetadataConfig) { c.Issuer += " " }},
		{"missing-authorization-endpoint", func(c *MCPExternalASMetadataConfig) { c.AuthorizationEndpoint = "" }},
		{"http-authorization-endpoint", func(c *MCPExternalASMetadataConfig) {
			c.AuthorizationEndpoint = "http://auth.example.test/oauth/authorize"
		}},
		{"foreign-authorization-endpoint", func(c *MCPExternalASMetadataConfig) {
			c.AuthorizationEndpoint = "https://auth.example.test.evil.test/oauth/authorize"
		}},
		{"authorization-userinfo", func(c *MCPExternalASMetadataConfig) {
			c.AuthorizationEndpoint = "https://name@auth.example.test/oauth/authorize"
		}},
		{"authorization-query", func(c *MCPExternalASMetadataConfig) { c.AuthorizationEndpoint += "?leak=1" }},
		{"authorization-fragment", func(c *MCPExternalASMetadataConfig) { c.AuthorizationEndpoint += "#frag" }},
		{"missing-token-endpoint", func(c *MCPExternalASMetadataConfig) { c.TokenEndpoint = "" }},
		{"http-token-endpoint", func(c *MCPExternalASMetadataConfig) { c.TokenEndpoint = "http://auth.example.test/oauth/token" }},
		{"foreign-token-endpoint", func(c *MCPExternalASMetadataConfig) { c.TokenEndpoint = "https://evil.test/oauth/token" }},
		{"token-encoded-path", func(c *MCPExternalASMetadataConfig) { c.TokenEndpoint += "%2Fother" }},
		{"token-query", func(c *MCPExternalASMetadataConfig) { c.TokenEndpoint += "?token=secret" }},
		{"same-endpoints", func(c *MCPExternalASMetadataConfig) { c.TokenEndpoint = c.AuthorizationEndpoint }},
		{"missing-scopes", func(c *MCPExternalASMetadataConfig) { c.SupportedStudentScopes = nil }},
		{"duplicate-scopes", func(c *MCPExternalASMetadataConfig) {
			c.SupportedStudentScopes = []string{"courses:read", "courses:read"}
		}},
		{"wildcard-scope", func(c *MCPExternalASMetadataConfig) { c.SupportedStudentScopes = []string{"*"} }},
		{"space-scope", func(c *MCPExternalASMetadataConfig) { c.SupportedStudentScopes = []string{"courses:read lessons:read"} }},
		{"too-many-scopes", func(c *MCPExternalASMetadataConfig) { c.SupportedStudentScopes = make([]string, 33) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := validMCPExternalASMetadataConfig()
			tc.change(&config)
			metadata, path, err := BuildMCPExternalASMetadata(config)
			if !errors.Is(err, ErrMCPExternalDenied) || metadata != nil || path != "" {
				t.Fatalf("metadata=%+v discovery=%q err=%v; want denied with no output", metadata, path, err)
			}
		})
	}
}
