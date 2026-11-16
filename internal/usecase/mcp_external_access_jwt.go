package usecase

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

// MCPExternalAccessJWTAuthority is distinct from Codechuman frontend/IDE
// sessions. Verification establishes cryptographic token validity only; the
// caller MUST check current Auth consent and RBAC before accepting a grant.
type MCPExternalAccessJWTAuthority struct {
	issuer      string
	resourceURI string
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	now         func() time.Time
}

func NewMCPExternalAccessJWTAuthority(issuer, resourceURI, privatePEM, publicPEM string) (*MCPExternalAccessJWTAuthority, error) {
	if _, ok := parseMCPExternalASHTTPSURL(issuer, false); !ok || !validMCPResourceURI(resourceURI) ||
		strings.TrimSpace(privatePEM) == "" || strings.TrimSpace(publicPEM) == "" {
		return nil, ErrMCPExternalDenied
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	if err != nil || privateKey.N.BitLen() < 2048 {
		return nil, ErrMCPExternalDenied
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	if err != nil || publicKey.N.Cmp(privateKey.N) != 0 || publicKey.E != privateKey.E {
		return nil, ErrMCPExternalDenied
	}
	return &MCPExternalAccessJWTAuthority{
		issuer: issuer, resourceURI: resourceURI, privateKey: privateKey,
		publicKey: publicKey, now: time.Now,
	}, nil
}

func (a *MCPExternalAccessJWTAuthority) Sign(intent *MCPExternalAccessTokenIntent) (string, error) {
	if a == nil || a.privateKey == nil || a.now == nil || intent == nil ||
		intent.Issuer != a.issuer || intent.Audience != a.resourceURI ||
		!validNonZeroCanonicalMCPUUID(intent.Subject) ||
		!validNonZeroCanonicalMCPUUID(intent.GrantID) ||
		intent.ClientID == "" || len(intent.ClientID) > 256 ||
		!validMCPTokenJTI(intent.JWTID) ||
		intent.IssuedAt <= 0 || intent.ExpiresAt <= intent.IssuedAt ||
		intent.ExpiresAt-intent.IssuedAt > int64(maxMCPExternalAccessTokenTTL/time.Second) {
		return "", ErrMCPExternalDenied
	}
	now := a.now().UTC().Unix()
	if intent.IssuedAt > now+5 || intent.IssuedAt < now-30 || intent.ExpiresAt <= now {
		return "", ErrMCPExternalDenied
	}
	scopes, valid := parseMCPRequestedScopes(intent.Scope)
	if !valid || !domain.ValidMCPStudentRequestedScopes(scopes) {
		return "", ErrMCPExternalDenied
	}
	claims := jwt.MapClaims{
		"iss": intent.Issuer, "sub": intent.Subject, "aud": intent.Audience,
		"client_id": intent.ClientID, "grant_id": intent.GrantID, "scope": intent.Scope,
		"iat": intent.IssuedAt, "exp": intent.ExpiresAt, "jti": intent.JWTID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = MCPExternalAccessTokenJOSEType
	signed, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", ErrMCPExternalDenied
	}
	return signed, nil
}

// VerifySignature checks token type, issuer, exact audience, signature and
// bounded claims. It does NOT attest current consent, role, scopes or revocation.
func (a *MCPExternalAccessJWTAuthority) VerifySignature(raw, resource string) (*MCPExternalAccessTokenIntent, error) {
	if a == nil || a.publicKey == nil || a.now == nil || resource != a.resourceURI ||
		len(raw) == 0 || len(raw) > 8192 {
		return nil, ErrMCPExternalDenied
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(a.issuer), jwt.WithAudience(a.resourceURI),
		jwt.WithIssuedAt(), jwt.WithExpirationRequired(), jwt.WithTimeFunc(a.now),
	).ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 || len(token.Header) != 2 ||
			token.Header["typ"] != MCPExternalAccessTokenJOSEType {
			return nil, errors.New("invalid external token header")
		}
		return a.publicKey, nil
	})
	if err != nil || parsed == nil || !parsed.Valid || len(claims) != 9 {
		return nil, ErrMCPExternalDenied
	}
	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	audience, _ := claims["aud"].(string)
	clientID, _ := claims["client_id"].(string)
	grantID, _ := claims["grant_id"].(string)
	scope, _ := claims["scope"].(string)
	jti, _ := claims["jti"].(string)
	iat, iatOK := exactMCPJWTInteger(claims["iat"])
	exp, expOK := exactMCPJWTInteger(claims["exp"])
	scopes, valid := parseMCPRequestedScopes(scope)
	now := a.now().UTC().Unix()
	if issuer != a.issuer || audience != resource ||
		!validNonZeroCanonicalMCPUUID(subject) || !validNonZeroCanonicalMCPUUID(grantID) ||
		clientID == "" || len(clientID) > 256 || !validMCPTokenJTI(jti) ||
		!iatOK || !expOK || iat <= 0 || iat > now+5 || exp <= now ||
		exp <= iat || exp-iat > int64(maxMCPExternalAccessTokenTTL/time.Second) ||
		!valid || !domain.ValidMCPStudentRequestedScopes(scopes) {
		return nil, ErrMCPExternalDenied
	}
	return &MCPExternalAccessTokenIntent{
		Issuer: issuer, Subject: subject, Audience: audience,
		ClientID: clientID, GrantID: grantID, Scope: scope,
		IssuedAt: iat, ExpiresAt: exp, JWTID: jti,
	}, nil
}

func validMCPTokenJTI(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == raw
}

func validNonZeroCanonicalMCPUUID(s string) bool {
	return canonicalReviewerUUID(s) && s != "00000000-0000-0000-0000-000000000000"
}

func exactMCPJWTInteger(raw any) (int64, bool) {
	switch n := raw.(type) {
	case float64:
		integer := int64(n)
		return integer, float64(integer) == n && integer > 0
	case int64:
		return n, n > 0
	default:
		return 0, false
	}
}
