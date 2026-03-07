package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/example/auth-service/internal/domain"
)

type oauthProviderConfig struct {
	clientID     string
	clientSecret string
	redirectURL  string
}

type oauthProfile struct {
	ProviderUserID string
	Email          string
	DisplayName    string
	RawProfile     map[string]interface{}
}

func (s *authService) OAuthCallback(ctx context.Context, traceID, provider, code string) (*domain.AuthUser, *Tokens, error) {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	if normalizedProvider != "google" && normalizedProvider != "github" {
		return nil, nil, fmt.Errorf("unsupported oauth provider")
	}
	if strings.TrimSpace(code) == "" {
		return nil, nil, fmt.Errorf("oauth code is required")
	}

	profile, err := s.exchangeOAuthCode(ctx, normalizedProvider, code)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(profile.ProviderUserID) == "" {
		return nil, nil, fmt.Errorf("provider user id is empty")
	}
	if strings.TrimSpace(profile.Email) == "" {
		return nil, nil, fmt.Errorf("provider did not return email")
	}
	profile.Email = normalizeEmail(profile.Email)

	var user *domain.AuthUser
	identity, identityErr := s.identities.FindByProvider(ctx, normalizedProvider, profile.ProviderUserID)
	switch {
	case identityErr == nil:
		user, err = s.users.FindByID(ctx, identity.UserID)
		if err != nil {
			return nil, nil, err
		}
	case errors.Is(identityErr, gorm.ErrRecordNotFound):
		user, err = s.users.FindByEmail(ctx, profile.Email)
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, nil, err
			}
			user, err = s.createOAuthUser(ctx, profile.Email)
			if err != nil {
				return nil, nil, err
			}
		}

		newIdentity := &domain.AuthIdentity{
			UserID:         user.ID,
			Provider:       normalizedProvider,
			ProviderUserID: profile.ProviderUserID,
			Email:          profile.Email,
			RawProfile:     profile.RawProfile,
		}
		if err := s.identities.Create(ctx, newIdentity); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, identityErr
	}

	now := time.Now().UTC()
	user.LastLoginAt = &now
	_ = s.users.Update(ctx, user)

	tokens, err := s.issueTokens(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	s.logger.Info().Str("trace_id", traceID).Str("provider", normalizedProvider).Str("user_id", user.ID).Msg("oauth signin")
	return user, tokens, nil
}

func (s *authService) createOAuthUser(ctx context.Context, email string) (*domain.AuthUser, error) {
	randomSecret := fmt.Sprintf("oauth:%d:%s", time.Now().UnixNano(), email)
	hash, err := bcrypt.GenerateFromPassword([]byte(randomSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &domain.AuthUser{
		Email:        email,
		PasswordHash: string(hash),
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	if s.userClient != nil {
		_ = s.userClient.CreateUser(ctx, user.ID, user.Email, "auth", "oauth")
	}
	if s.rbacClient != nil {
		_ = s.rbacClient.AssignRole(ctx, user.ID, s.cfg.DefaultRole)
	}
	return user, nil
}

func (s *authService) exchangeOAuthCode(ctx context.Context, provider, code string) (*oauthProfile, error) {
	conf, err := s.oauthConfigForProvider(provider)
	if err != nil {
		return nil, err
	}

	switch provider {
	case "google":
		accessToken, err := exchangeGoogleCode(ctx, conf, code)
		if err != nil {
			return nil, err
		}
		return fetchGoogleProfile(ctx, accessToken)
	case "github":
		accessToken, err := exchangeGitHubCode(ctx, conf, code)
		if err != nil {
			return nil, err
		}
		return fetchGitHubProfile(ctx, accessToken)
	default:
		return nil, fmt.Errorf("unsupported oauth provider")
	}
}

func (s *authService) oauthConfigForProvider(provider string) (oauthProviderConfig, error) {
	switch provider {
	case "google":
		if s.cfg.OAuthGoogleClientID == "" || s.cfg.OAuthGoogleClientSecret == "" || s.cfg.OAuthGoogleRedirectURL == "" {
			return oauthProviderConfig{}, fmt.Errorf("google oauth is not configured")
		}
		return oauthProviderConfig{
			clientID:     s.cfg.OAuthGoogleClientID,
			clientSecret: s.cfg.OAuthGoogleClientSecret,
			redirectURL:  s.cfg.OAuthGoogleRedirectURL,
		}, nil
	case "github":
		if s.cfg.OAuthGitHubClientID == "" || s.cfg.OAuthGitHubClientSecret == "" || s.cfg.OAuthGitHubRedirectURL == "" {
			return oauthProviderConfig{}, fmt.Errorf("github oauth is not configured")
		}
		return oauthProviderConfig{
			clientID:     s.cfg.OAuthGitHubClientID,
			clientSecret: s.cfg.OAuthGitHubClientSecret,
			redirectURL:  s.cfg.OAuthGitHubRedirectURL,
		}, nil
	default:
		return oauthProviderConfig{}, fmt.Errorf("unsupported oauth provider")
	}
}

func exchangeGoogleCode(ctx context.Context, cfg oauthProviderConfig, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cfg.clientID)
	form.Set("client_secret", cfg.clientSecret)
	form.Set("redirect_uri", cfg.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var payload struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		if payload.Error != "" {
			return "", fmt.Errorf("google token exchange failed: %s", payload.Error)
		}
		return "", fmt.Errorf("google token exchange failed: %s", resp.Status)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("google token exchange returned empty access token")
	}
	return payload.AccessToken, nil
}

func fetchGoogleProfile(ctx context.Context, accessToken string) (*oauthProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified bool   `json:"email_verified"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("google userinfo failed: %s", resp.Status)
	}

	raw := map[string]interface{}{
		"sub":            payload.Sub,
		"email":          payload.Email,
		"name":           payload.Name,
		"email_verified": payload.EmailVerified,
		"picture":        payload.Picture,
	}

	return &oauthProfile{
		ProviderUserID: payload.Sub,
		Email:          payload.Email,
		DisplayName:    payload.Name,
		RawProfile:     raw,
	}, nil
}

func exchangeGitHubCode(ctx context.Context, cfg oauthProviderConfig, code string) (string, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", cfg.clientID)
	form.Set("client_secret", cfg.clientSecret)
	form.Set("redirect_uri", cfg.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var payload struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		if payload.Error != "" {
			return "", fmt.Errorf("github token exchange failed: %s", payload.Error)
		}
		return "", fmt.Errorf("github token exchange failed: %s", resp.Status)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("github token exchange returned empty access token")
	}
	return payload.AccessToken, nil
}

func fetchGitHubProfile(ctx context.Context, accessToken string) (*oauthProfile, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	userReq.Header.Set("Authorization", "Bearer "+accessToken)
	userReq.Header.Set("Accept", "application/vnd.github+json")
	userReq.Header.Set("User-Agent", "ms-go-auth")

	userResp, err := client.Do(userReq)
	if err != nil {
		return nil, err
	}
	defer userResp.Body.Close()

	var userPayload struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userPayload); err != nil {
		return nil, err
	}
	if userResp.StatusCode >= 400 {
		return nil, fmt.Errorf("github userinfo failed: %s", userResp.Status)
	}

	email := userPayload.Email
	if strings.TrimSpace(email) == "" {
		emailsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
		if err != nil {
			return nil, err
		}
		emailsReq.Header.Set("Authorization", "Bearer "+accessToken)
		emailsReq.Header.Set("Accept", "application/vnd.github+json")
		emailsReq.Header.Set("User-Agent", "ms-go-auth")

		emailsResp, err := client.Do(emailsReq)
		if err != nil {
			return nil, err
		}
		defer emailsResp.Body.Close()

		var emailsPayload []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.NewDecoder(emailsResp.Body).Decode(&emailsPayload); err != nil {
			return nil, err
		}
		if emailsResp.StatusCode >= 400 {
			return nil, fmt.Errorf("github emails failed: %s", emailsResp.Status)
		}

		for _, item := range emailsPayload {
			if item.Primary && item.Verified && item.Email != "" {
				email = item.Email
				break
			}
		}
		if email == "" {
			for _, item := range emailsPayload {
				if item.Verified && item.Email != "" {
					email = item.Email
					break
				}
			}
		}
	}

	displayName := userPayload.Name
	if strings.TrimSpace(displayName) == "" {
		displayName = userPayload.Login
	}

	raw := map[string]interface{}{
		"id":         userPayload.ID,
		"login":      userPayload.Login,
		"name":       userPayload.Name,
		"email":      email,
		"avatar_url": userPayload.AvatarURL,
	}

	return &oauthProfile{
		ProviderUserID: fmt.Sprintf("%d", userPayload.ID),
		Email:          email,
		DisplayName:    displayName,
		RawProfile:     raw,
	}, nil
}
