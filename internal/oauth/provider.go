package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type ProviderName string

const (
	ProviderGoogle ProviderName = "google"
	ProviderGitHub ProviderName = "github"
)

type Profile struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	DisplayName    string
	FirstName      string
	LastName       string
	BirthYear      *int
	Gender         string
	AvatarURL      string
	RawProfile     map[string]interface{}
}

type Provider interface {
	Name() ProviderName
	Validate() error
	AuthorizationURL(state, verifier string) string
	Authenticate(ctx context.Context, code, verifier string) (*Profile, error)
}

type Registry struct {
	providers map[ProviderName]Provider
}

func NewRegistry(providers ...Provider) *Registry {
	registry := &Registry{providers: make(map[ProviderName]Provider, len(providers))}
	for _, provider := range providers {
		if provider != nil {
			registry.providers[provider.Name()] = provider
		}
	}
	return registry
}

func (r *Registry) Get(name string) (Provider, error) {
	normalized := ProviderName(strings.ToLower(strings.TrimSpace(name)))
	provider, ok := r.providers[normalized]
	if !ok {
		return nil, fmt.Errorf("unsupported oauth provider")
	}
	if err := provider.Validate(); err != nil {
		return nil, err
	}
	return provider, nil
}

type OAuth2Base struct {
	ProviderName ProviderName
	Config       oauth2.Config
	HTTPClient   *http.Client
}

func (b *OAuth2Base) Name() ProviderName { return b.ProviderName }

func (b *OAuth2Base) Validate() error {
	if strings.TrimSpace(b.Config.ClientID) == "" || strings.TrimSpace(b.Config.ClientSecret) == "" || strings.TrimSpace(b.Config.RedirectURL) == "" {
		return fmt.Errorf("%s oauth is not configured", b.ProviderName)
	}
	if strings.TrimSpace(b.Config.Endpoint.AuthURL) == "" || strings.TrimSpace(b.Config.Endpoint.TokenURL) == "" {
		return fmt.Errorf("%s oauth endpoints are not configured", b.ProviderName)
	}
	return nil
}

func (b *OAuth2Base) AuthorizationURL(state, verifier string) string {
	return b.Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (b *OAuth2Base) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	if b.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, b.HTTPClient)
	}
	return b.Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
}

func (b *OAuth2Base) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	if b.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, b.HTTPClient)
	}
	return b.Config.Client(ctx, token)
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func birthYearFromClaim(value string) *int {
	value = strings.TrimSpace(value)
	if len(value) < 4 || value[:4] == "0000" {
		return nil
	}
	year, err := strconv.Atoi(value[:4])
	if err != nil || year < 1900 || year > time.Now().UTC().Year() {
		return nil
	}
	return &year
}
