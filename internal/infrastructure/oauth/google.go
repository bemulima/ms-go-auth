package oauth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
)

const googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

type GoogleOAuth2 struct {
	*OAuth2Base
	userInfoURL string
	JWKSURL     string
}

func NewGoogleOAuth2(clientID, clientSecret, redirectURL string) *GoogleOAuth2 {
	return &GoogleOAuth2{
		OAuth2Base: &OAuth2Base{
			ProviderName: ProviderGoogle,
			HTTPClient:   defaultHTTPClient(),
			Config: oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  redirectURL,
				Scopes:       []string{"openid", "email", "profile"},
				Endpoint:     googleoauth.Endpoint,
			},
		},
		userInfoURL: googleUserInfoURL,
		JWKSURL:     "https://www.googleapis.com/oauth2/v3/certs",
	}
}

func (p *GoogleOAuth2) Authenticate(ctx context.Context, code, verifier string) (*Profile, error) {
	token, err := p.Exchange(ctx, code, verifier)
	if err != nil {
		return nil, fmt.Errorf("google token exchange failed: %w", err)
	}

	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("google ID token required")
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("google signing key required")
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, p.JWKSURL, nil)
		if e != nil {
			return nil, e
		}
		resp, e := p.HTTPClient.Do(req)
		if e != nil {
			return nil, fmt.Errorf("google keys unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("google keys unavailable")
		}
		var keys struct {
			Keys []struct{ Kid, Kty, Alg, N, E string }
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&keys) != nil {
			return nil, fmt.Errorf("invalid google keys")
		}
		for _, k := range keys.Keys {
			if k.Kid != kid || k.Kty != "RSA" || k.Alg != "RS256" {
				continue
			}
			n, e := base64.RawURLEncoding.DecodeString(k.N)
			if e != nil {
				return nil, e
			}
			b, e := base64.RawURLEncoding.DecodeString(k.E)
			if e != nil || len(b) > 4 {
				return nil, fmt.Errorf("invalid key")
			}
			exponent := 0
			for _, v := range b {
				exponent = exponent*256 + int(v)
			}
			if len(n) < 256 || exponent < 3 {
				return nil, fmt.Errorf("invalid key")
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, nil
		}
		return nil, fmt.Errorf("google signing key not found")
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(p.Config.ClientID), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("google ID token invalid")
	}
	issuer, _ := claims["iss"].(string)
	if issuer != "https://accounts.google.com" && issuer != "accounts.google.com" {
		return nil, fmt.Errorf("google issuer invalid")
	}
	if claims["nonce"] != googleNonce(verifier) {
		return nil, fmt.Errorf("google nonce invalid")
	}
	client := p.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google userinfo failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("google userinfo failed: %s", resp.Status)
	}

	var payload struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Birthdate     string `json:"birthdate"`
		Gender        string `json:"gender"`
		EmailVerified bool   `json:"email_verified"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode google userinfo: %w", err)
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	verified, _ := claims["email_verified"].(bool)
	hd, _ := claims["hd"].(string)
	if sub == "" || sub != payload.Sub || !strings.EqualFold(email, payload.Email) {
		return nil, fmt.Errorf("google identity mismatch")
	}
	trusted := verified && (strings.HasSuffix(strings.ToLower(email), "@gmail.com") || hd != "")
	return &Profile{
		ProviderUserID: strings.TrimSpace(payload.Sub),
		Email:          strings.TrimSpace(payload.Email),
		EmailVerified:  trusted,
		DisplayName:    strings.TrimSpace(payload.Name),
		FirstName:      strings.TrimSpace(payload.GivenName),
		LastName:       strings.TrimSpace(payload.FamilyName),
		BirthYear:      birthYearFromClaim(payload.Birthdate),
		Gender:         strings.ToLower(strings.TrimSpace(payload.Gender)),
		AvatarURL:      strings.TrimSpace(payload.Picture),
		RawProfile: map[string]interface{}{
			"sub":            payload.Sub,
			"email":          payload.Email,
			"name":           payload.Name,
			"given_name":     payload.GivenName,
			"family_name":    payload.FamilyName,
			"birthdate":      payload.Birthdate,
			"gender":         payload.Gender,
			"email_verified": payload.EmailVerified,
			"picture":        payload.Picture,
		},
	}, nil
}

func googleNonce(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func (p *GoogleOAuth2) AuthorizationURL(state, verifier string) string {
	return p.Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", googleNonce(verifier)))
}

// UseLocalBoundary redirects only external Google endpoints, retaining real validation.
func (p *GoogleOAuth2) UseLocalBoundary(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("OAuth boundary must be a loopback HTTP origin with an explicit port")
	}
	base = strings.TrimRight(base, "/")
	p.Config.Endpoint = oauth2.Endpoint{AuthURL: base + "/provider/google/authorize", TokenURL: base + "/provider/google/token", AuthStyle: oauth2.AuthStyleInParams}
	p.userInfoURL = base + "/provider/google/userinfo"
	p.JWKSURL = base + "/provider/google/keys"
	return nil
}
