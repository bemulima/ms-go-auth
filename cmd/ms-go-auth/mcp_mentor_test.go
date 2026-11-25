package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/domain"
	private "github.com/example/auth-service/internal/transport/http/private"
)

func TestMCPMentorMetadataUsesDistinctRFC8414IssuerAndCanonicalGatewayRoutes(t *testing.T) {
	m, path, err := mcpMentorMetadata("https://api.example.test/mentor", false, false, false)
	if err != nil || path != "/.well-known/oauth-authorization-server/mentor" || m.Issuer != "https://api.example.test/mentor" || m.AuthorizationEndpoint != "https://api.example.test/api/auth/v1/auth/mcp/mentor/authorize" || m.TokenEndpoint != "https://api.example.test/api/auth/v1/auth/mcp/mentor/token" || len(m.ScopesSupported) != 1 || m.ScopesSupported[0] != domain.MCPMentorScope || len(m.GrantTypesSupported) != 1 || m.GrantTypesSupported[0] != "authorization_code" || len(m.CodeChallengeMethodsSupported) != 1 || m.CodeChallengeMethodsSupported[0] != "S256" {
		t.Fatalf("metadata mismatch: %+v %s %v", m, path, err)
	}
	for _, bad := range []string{"http://api.example.test/mentor", "https://api.example.test", "https://api.example.test/mentor/", "https://api.example.test/mentor?x=1", "https://api.example.test/%6dentor"} {
		if _, _, err := mcpMentorMetadata(bad, false, false, false); err == nil {
			t.Fatal("invalid issuer admitted")
		}
	}
}
func TestMCPMentorConfigDisabledAndPartialEnableFailClosed(t *testing.T) {
	if err := validateMCPMentorConfig(&config.Config{}); err != nil {
		t.Fatal("disabled feature required keys")
	}
	if err := validateMCPMentorConfig(&config.Config{MCPMentorEnabled: true, DBMigrateOnStart: true}); err == nil {
		t.Fatal("enabled feature allowed startup migrations/absent authority")
	}
	for _, value := range []string{"", strings.Repeat("A", 31), strings.Repeat("A", 4097), strings.Repeat("A", 32) + ",x", strings.Repeat("A", 32) + " ", "example" + strings.Repeat("A", 40), strings.Repeat("A", 32) + "\n"} {
		if private.ValidMCPPersonaCapability(value) {
			t.Fatal("unsafe verification capability accepted")
		}
	}
	if !private.ValidMCPPersonaCapability(strings.Repeat("K", 48)) {
		t.Fatal("valid independent capability rejected")
	}
}

func TestMCPMentorConfigRequiresSeparateIssuerKeysAndResourceBinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	rbacPublic := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherPub}))
	base := config.Config{MCPMentorEnabled: true, MCPStudentEnabled: true, HTTPBasePath: "/api/v1", JWTIssuer: "auth-service", MCPIssuerURI: "https://api.example.test", MCPResourceURI: "https://api.example.test/mcp", MCPMentorIssuer: "https://api.example.test/mentor", MCPMentorResource: "https://api.example.test/mcp", MCPMentorConsentUI: "https://mentor.example.test/mentor/mcp/consent", MCPMentorPrivateKey: private, MCPMentorPublicKey: public, MCPMentorRBACPublicKey: rbacPublic, MCPMentorApprovalURL: "https://mentor-owner.example.test/internal/mcp/v1/mentor/approval", MCPMentorApprovalToken: strings.Repeat("A", 48), MCPAdapterVerifyCapability: strings.Repeat("K", 48), MCPMentorAccessTTL: 5 * time.Minute, MCPMentorConsentTTL: 24 * time.Hour}
	if err := validateMCPMentorConfig(&base); err != nil {
		t.Fatal("valid inert configuration rejected")
	}
	for name, edit := range map[string]func(*config.Config){
		"Student issuer collision": func(c *config.Config) { c.MCPIssuerURI = c.MCPMentorIssuer },
		"web issuer collision":     func(c *config.Config) { c.JWTIssuer = c.MCPMentorIssuer },
		"same modulus another exponent": func(c *config.Config) {
			altered := rsa.PublicKey{N: key.N, E: 3}
			der, _ := x509.MarshalPKIXPublicKey(&altered)
			c.JWTPublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		},
		"web signing key reuse":      func(c *config.Config) { c.JWTPublicKey = c.MCPMentorPublicKey },
		"decision signing key reuse": func(c *config.Config) { c.MCPMentorRBACPublicKey = c.MCPMentorPublicKey },
		"resource split":             func(c *config.Config) { c.MCPResourceURI = "https://other.example.test/mcp" },
		"capability reuse":           func(c *config.Config) { c.MCPMentorApprovalToken = c.MCPAdapterVerifyCapability },
		"capability comma":           func(c *config.Config) { c.MCPAdapterVerifyCapability += ",extra" },
		"startup migrations":         func(c *config.Config) { c.DBMigrateOnStart = true },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			edit(&cfg)
			if validateMCPMentorConfig(&cfg) == nil {
				t.Fatal("unsafe enabled configuration accepted")
			}
		})
	}
}
