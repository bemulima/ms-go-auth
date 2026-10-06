package unit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	taraclient "github.com/example/auth-service/internal/infrastructure/http/tarantool"
)

type tarantoolRequest struct {
	path string
	body map[string]any
}

func TestTarantoolHTTPClientUsesCanonicalFlowEndpoints(t *testing.T) {
	t.Helper()

	var signupRequests []tarantoolRequest
	var emailChangeRequests []tarantoolRequest

	decode := func(r *http.Request) tarantoolRequest {
		t.Helper()
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type = %q, want application/json", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return tarantoolRequest{path: r.URL.Path, body: body}
	}

	signupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signupRequests = append(signupRequests, decode(r))
		switch r.URL.Path {
		case "/api/v1/set-new-user", "/api/v1/password-reset-verify":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/check-new-user-code":
			_, _ = w.Write([]byte(`{"password":"password-hash"}`))
		case "/api/v1/password-reset-start":
			_, _ = w.Write([]byte(`{"uuid":"reset-uuid"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer signupServer.Close()

	emailChangeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		emailChangeRequests = append(emailChangeRequests, decode(r))
		switch r.URL.Path {
		case "/api/v1/start-email-change":
			_, _ = w.Write([]byte(`{"uuid":"email-uuid"}`))
		case "/api/v1/verify-email-change":
			_, _ = w.Write([]byte(`{"user_id":"user-1","email":"new@example.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer emailChangeServer.Close()

	client := taraclient.NewHTTPClient(signupServer.URL, emailChangeServer.URL, time.Second)
	ctx := context.Background()
	if err := client.StartSignup(ctx, "user@example.com", "password-hash"); err != nil {
		t.Fatalf("start signup: %v", err)
	}
	if passwordHash, err := client.VerifySignup(ctx, "user@example.com", "signup-code"); err != nil || passwordHash != "password-hash" {
		t.Fatalf("verify signup = %q, %v", passwordHash, err)
	}
	if uuid, err := client.StartEmailChange(ctx, "user-1", "new@example.com"); err != nil || uuid != "email-uuid" {
		t.Fatalf("start email change = %q, %v", uuid, err)
	}
	if userID, email, err := client.VerifyEmailChange(ctx, "email-code"); err != nil || userID != "user-1" || email != "new@example.com" {
		t.Fatalf("verify email change = %q, %q, %v", userID, email, err)
	}
	if uuid, err := client.StartPasswordReset(ctx, "user@example.com"); err != nil || uuid != "reset-uuid" {
		t.Fatalf("start password reset = %q, %v", uuid, err)
	}
	if err := client.VerifyPasswordReset(ctx, "user@example.com", "reset-code"); err != nil {
		t.Fatalf("verify password reset: %v", err)
	}

	assertTarantoolRequest(t, signupRequests[0], "/api/v1/set-new-user", map[string]any{"email": "user@example.com", "password": "password-hash"})
	assertTarantoolRequest(t, signupRequests[1], "/api/v1/check-new-user-code", map[string]any{"email": "user@example.com", "code": "signup-code"})
	assertTarantoolRequest(t, signupRequests[2], "/api/v1/password-reset-start", map[string]any{"email": "user@example.com"})
	assertTarantoolRequest(t, signupRequests[3], "/api/v1/password-reset-verify", map[string]any{"email": "user@example.com", "code": "reset-code"})
	assertTarantoolRequest(t, emailChangeRequests[0], "/api/v1/start-email-change", map[string]any{"user_id": "user-1", "email": "new@example.com"})
	assertTarantoolRequest(t, emailChangeRequests[1], "/api/v1/verify-email-change", map[string]any{"code": "email-code"})
}

func TestTarantoolHTTPClientTranslatesIdentityAbsence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer server.Close()

	client := taraclient.NewHTTPClient(server.URL, server.URL, time.Second)
	err := client.StartSignup(context.Background(), "user@example.com", "password-hash")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("start signup error = %v, want declared absence", err)
	}
}

func assertTarantoolRequest(t *testing.T, got tarantoolRequest, wantPath string, wantValue map[string]any) {
	t.Helper()
	if got.path != wantPath {
		t.Fatalf("path = %q, want %q", got.path, wantPath)
	}
	value, ok := got.body["value"].(map[string]any)
	if !ok {
		t.Fatalf("body = %#v, want value object", got.body)
	}
	if len(value) != len(wantValue) {
		t.Fatalf("value = %#v, want %#v", value, wantValue)
	}
	for key, want := range wantValue {
		if value[key] != want {
			t.Fatalf("value[%q] = %#v, want %#v", key, value[key], want)
		}
	}
}

func TestT16TarantoolRecoveryHTTPContract(t *testing.T) {
	const operation = "11111111-1111-4111-8111-111111111111"
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/consume-signup-proof" || r.Method != http.MethodPost {
			t.Error("wrong recovery endpoint")
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("X-Internal-Token") != "test-internal-token" {
			t.Error("missing internal authentication")
			w.WriteHeader(401)
			return
		}
		var payload struct {
			Value map[string]string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error("malformed payload")
			return
		}
		if len(payload.Value) != 3 || payload.Value["operation_id"] != operation || payload.Value["email"] != "test@example.test" || payload.Value["code"] != "test-proof" {
			t.Error("proof owner payload mismatch")
			w.WriteHeader(400)
			return
		}
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(domain.SignupProofReceipt{OperationID: operation, Email: "test@example.test", PasswordHash: "private-test-hash", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	}))
	defer server.Close()
	client := taraclient.NewHTTPClientWithSignupRecovery(server.URL, server.URL, "test-internal-token", time.Second).(domain.SignupProofConsumer)
	receipt, err := client.ConsumeSignupProof(context.Background(), "test@example.test", "test-proof", operation)
	if err != nil || receipt == nil || receipt.OperationID != operation || calls != 2 {
		t.Fatal("retry failed to retain exact operation binding")
	}
}
func TestT16TarantoolRecoveryMissingConfigFailsClosed(t *testing.T) {
	for _, client := range []domain.VerificationClient{taraclient.NewHTTPClient("http://127.0.0.1:1", "", time.Second), taraclient.NewHTTPClientWithSignupRecovery("", "", "test-internal-token", time.Second)} {
		_, err := client.(domain.SignupProofConsumer).ConsumeSignupProof(context.Background(), "test@example.test", "test-proof", "operation")
		if err == nil {
			t.Fatal("missing recovery configuration accepted")
		}
	}
}
func TestT16TarantoolRecoveryRejectsReceiptBinding(t *testing.T) {
	for _, phase := range []string{"operation", "email", "expiry"} {
		t.Run(phase, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				receipt := domain.SignupProofReceipt{OperationID: "operation", Email: "test@example.test", PasswordHash: "private-test-hash", ExpiresAt: time.Now().UTC().Add(time.Hour)}
				switch phase {
				case "operation":
					receipt.OperationID = "other"
				case "email":
					receipt.Email = "other@example.test"
				case "expiry":
					receipt.ExpiresAt = time.Now().UTC().Add(-time.Second)
				}
				_ = json.NewEncoder(w).Encode(receipt)
			}))
			defer server.Close()
			client := taraclient.NewHTTPClientWithSignupRecovery(server.URL, server.URL, "test-internal-token", time.Second).(domain.SignupProofConsumer)
			if _, err := client.ConsumeSignupProof(context.Background(), "test@example.test", "test-proof", "operation"); err == nil {
				t.Fatal("mismatched receipt accepted")
			}
		})
	}
}
