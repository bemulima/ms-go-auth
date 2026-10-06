package tarantool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/example/auth-service/internal/domain"
)

type httpClient struct {
	signupURL      string
	emailChangeURL string
	client         *http.Client
	internalToken  string
}

// NewHTTPClient builds the canonical HTTP transport for signup and related
// Tarantool flows in the target architecture.
func NewHTTPClient(signupURL, emailChangeURL string, timeout time.Duration) domain.VerificationClient {
	return &httpClient{signupURL: signupURL, emailChangeURL: emailChangeURL, client: &http.Client{Timeout: timeout}}
}

// NewHTTPClientWithSignupRecovery enables only the protected recoverable
// consume endpoint. Missing configuration fails before issuing a request.
func NewHTTPClientWithSignupRecovery(signupURL, emailChangeURL, internalToken string, timeout time.Duration) domain.VerificationClient {
	return &httpClient{signupURL: signupURL, emailChangeURL: emailChangeURL, internalToken: internalToken, client: &http.Client{Timeout: timeout}}
}

func (c *httpClient) ConsumeSignupProof(ctx context.Context, email, code, operationID string) (*domain.SignupProofReceipt, error) {
	if strings.TrimSpace(c.internalToken) == "" || strings.TrimSpace(c.signupURL) == "" || operationID == "" {
		return nil, fmt.Errorf("signup recovery configuration unavailable")
	}
	payload := map[string]interface{}{"value": map[string]string{"email": email, "code": code, "operation_id": operationID}}
	var receipt domain.SignupProofReceipt
	if err := c.post(ctx, c.signupURL, "/api/v1/consume-signup-proof", payload, &receipt); err != nil {
		return nil, err
	}
	if receipt.OperationID != operationID || receipt.Email != email || receipt.PasswordHash == "" || !receipt.ExpiresAt.After(time.Now().UTC()) {
		return nil, fmt.Errorf("signup receipt binding or expiry mismatch")
	}
	return &receipt, nil
}

func (c *httpClient) StartSignup(ctx context.Context, email, passwordHash string) error {
	payload := map[string]interface{}{"value": map[string]string{"email": email, "password": passwordHash}}
	return c.post(ctx, c.signupURL, "/api/v1/set-new-user", payload, nil)
}

func (c *httpClient) VerifySignup(ctx context.Context, email, code string) (string, error) {
	payload := map[string]interface{}{"value": map[string]string{"email": email, "code": code}}
	var resp struct {
		Password string `json:"password"`
	}
	if err := c.post(ctx, c.signupURL, "/api/v1/check-new-user-code", payload, &resp); err != nil {
		return "", err
	}
	return resp.Password, nil
}

func (c *httpClient) StartEmailChange(ctx context.Context, userID, newEmail string) (string, error) {
	payload := map[string]interface{}{"value": map[string]string{"user_id": userID, "email": newEmail}}
	var resp struct {
		UUID string `json:"uuid"`
	}
	if err := c.post(ctx, c.emailChangeURL, "/api/v1/start-email-change", payload, &resp); err != nil {
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
	if err := c.post(ctx, c.emailChangeURL, "/api/v1/verify-email-change", payload, &resp); err != nil {
		return "", "", err
	}
	return resp.UserID, resp.NewEmail, nil
}

func (c *httpClient) StartPasswordReset(ctx context.Context, email string) (string, error) {
	payload := map[string]interface{}{"value": map[string]string{"email": email}}
	var resp struct {
		UUID string `json:"uuid"`
	}
	if err := c.post(ctx, c.signupURL, "/api/v1/password-reset-start", payload, &resp); err != nil {
		return "", err
	}
	return resp.UUID, nil
}

func (c *httpClient) VerifyPasswordReset(ctx context.Context, email, code string) error {
	payload := map[string]interface{}{"value": map[string]string{"email": email, "code": code}}
	return c.post(ctx, c.signupURL, "/api/v1/password-reset-verify", payload, nil)
}

func (c *httpClient) post(ctx context.Context, baseURL, path string, payload interface{}, out interface{}) error {
	op := func() error {
		body, err := json.Marshal(payload)
		if err != nil {
			return backoff.Permanent(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s%s", baseURL, path), bytes.NewReader(body))
		if err != nil {
			return backoff.Permanent(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if path == "/api/v1/consume-signup-proof" {
			req.Header.Set("X-Internal-Token", c.internalToken)
		}
		res, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode == http.StatusNotFound {
			return backoff.Permanent(domain.ErrNotFound)
		}
		if path == "/api/v1/consume-signup-proof" && res.StatusCode >= 400 && res.StatusCode < 500 {
			return backoff.Permanent(fmt.Errorf("tarantool error: %d", res.StatusCode))
		}
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
