package tarantool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
)

type Client interface {
	StartSignup(ctx context.Context, email string) (string, error)
	VerifySignup(ctx context.Context, email, code string) error
	StartEmailChange(ctx context.Context, userID, newEmail string) (string, error)
	VerifyEmailChange(ctx context.Context, code string) (string, string, error)
	StartPasswordReset(ctx context.Context, email string) (string, error)
	VerifyPasswordReset(ctx context.Context, email, code string) error
}

type httpClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPClient(baseURL string, timeout time.Duration) Client {
	return &httpClient{baseURL: baseURL, client: &http.Client{Timeout: timeout}}
}

func (c *httpClient) StartSignup(ctx context.Context, email string) (string, error) {
	payload := map[string]interface{}{"value": map[string]string{"email": email}}
	var resp struct {
		UUID string `json:"uuid"`
	}
	if err := c.post(ctx, "/api/v1/set-new-user", payload, &resp); err != nil {
		return "", err
	}
	return resp.UUID, nil
}

func (c *httpClient) VerifySignup(ctx context.Context, email, code string) error {
	payload := map[string]interface{}{"value": map[string]string{"uuid": email, "code": code}}
	return c.post(ctx, "/api/v1/check-new-user-code", payload, nil)
}

func (c *httpClient) StartEmailChange(ctx context.Context, userID, newEmail string) (string, error) {
	payload := map[string]interface{}{"value": map[string]string{"user_id": userID, "email": newEmail}}
	var resp struct {
		UUID string `json:"uuid"`
	}
	if err := c.post(ctx, "/api/v1/start-email-change", payload, &resp); err != nil {
		return "", err
	}
	return resp.UUID, nil
}

func (c *httpClient) VerifyEmailChange(ctx context.Context, code string) (string, string, error) {
	payload := map[string]interface{}{"value": map[string]string{"code": code}}
	var resp struct {
		UserID   string `json:"user_id"`
		NewEmail string `json:"email"`
	}
	if err := c.post(ctx, "/api/v1/verify-email-change", payload, &resp); err != nil {
		return "", "", err
	}
	return resp.UserID, resp.NewEmail, nil
}

func (c *httpClient) StartPasswordReset(ctx context.Context, email string) (string, error) {
	payload := map[string]interface{}{"value": map[string]string{"email": email}}
	var resp struct {
		UUID string `json:"uuid"`
	}
	if err := c.post(ctx, "/password-reset-start", payload, &resp); err != nil {
		return "", err
	}
	return resp.UUID, nil
}

func (c *httpClient) VerifyPasswordReset(ctx context.Context, email, code string) error {
	payload := map[string]interface{}{"value": map[string]string{"email": email, "code": code}}
	return c.post(ctx, "/password-reset-verify", payload, nil)
}

func (c *httpClient) post(ctx context.Context, path string, payload interface{}, out interface{}) error {
	op := func() error {
		body, err := json.Marshal(payload)
		if err != nil {
			return backoff.Permanent(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s%s", c.baseURL, path), bytes.NewReader(body))
		if err != nil {
			return backoff.Permanent(err)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode >= 400 {
			return fmt.Errorf("tarantool error: %d", res.StatusCode)
		}
		if out != nil {
			if err := json.NewDecoder(res.Body).Decode(out); err != nil {
				return backoff.Permanent(err)
			}
		}
		return nil
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 200 * time.Millisecond
	bo.MaxElapsedTime = 3 * time.Second
	return backoff.Retry(op, backoff.WithContext(bo, ctx))
}
