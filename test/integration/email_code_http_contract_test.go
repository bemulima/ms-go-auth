//go:build integration

package usecase_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	store "github.com/example/auth-service/internal/infrastructure/persistence/tarantool"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/example/auth-service/internal/transport/http/api/v1"
	"github.com/example/auth-service/internal/transport/http/api/v1/handlers"
	"github.com/labstack/echo/v4"
)

// Check the owner contract against actual Echo registration and inbound handlers.
// Invalid JSON must be rejected before any credential, delivery or storage effect.
func TestEmailCodeHTTPContract(t *testing.T) {
	contract, err := os.ReadFile("../../.ai/contracts/http.yaml")
	if err != nil {
		t.Fatal("owned HTTP contract unavailable")
	}
	var public []string
	for _, line := range strings.Split(string(contract), "\n") {
		if strings.HasPrefix(line, "public_post: [") {
			public = strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "public_post: ["), "]"), ",")
		}
	}
	declared := map[string]bool{}
	for _, path := range public {
		path = strings.TrimSpace(path)
		if strings.HasPrefix(path, "/code/") {
			declared[path] = true
		}
	}
	if len(declared) != 6 {
		t.Fatal("owned contract must declare exactly six code operations")
	}
	e := echo.New()
	e.HideBanner = true
	apiv1.NewRouter(handlers.NewAuthHandler(nil), func(next echo.HandlerFunc) echo.HandlerFunc { return next }).Register(e.Group("/api/v1"))
	for _, purpose := range []string{"registration", "reset"} {
		for _, action := range []string{"start", "verify", "complete"} {
			path := "/code/" + purpose + "/" + action
			t.Run(purpose+"/"+action, func(t *testing.T) {
				if !declared[path] {
					t.Fatal("operation missing from owned contract")
				}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/auth"+path, strings.NewReader("{"))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
				response := httptest.NewRecorder()
				e.ServeHTTP(response, req)
				if response.Code != http.StatusBadRequest {
					t.Fatal("mounted handler did not reject malformed JSON")
				}
			})
		}
	}
}

// Exercise migration 005 through the production binary adapter with only its
// named-CALL runtime principal. Separate connections prove persisted state.
func TestEmailCodeLiveTarantool(t *testing.T) {
	if os.Getenv("T16_DIRECT_VERIFICATION") != "true" {
		t.Skip("requires isolated canonical identity store")
	}
	address := os.Getenv("AUTH_VERIFICATION_TEST_TARANTOOL_ADDRESS")
	host, port, err := net.SplitHostPort(address)
	user, password, prefix := os.Getenv("AUTH_VERIFICATION_TEST_TARANTOOL_USER"), os.Getenv("AUTH_VERIFICATION_TEST_TARANTOOL_PASSWORD"), os.Getenv("T16_RUN_PREFIX")
	if err != nil || (host != "127.0.0.1" && host != "localhost") || port == "" || user == "" || user == "admin" || user == "guest" || password == "" || prefix == "" || strings.ContainsAny(prefix, " @/\\") {
		t.Fatal("owned loopback identity store required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func() *store.Client {
		t.Helper()
		c, err := store.Connect(ctx, store.ConnectionConfig{Address: address, User: user, Password: password, RequestTimeout: 3 * time.Second})
		if err != nil {
			t.Fatal("production verification adapter connection")
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	first, second := connect(), connect()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("private test HMAC key")
	}
	digest := func(value string) string {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(value))
		return hex.EncodeToString(h.Sum(nil))
	}
	call := func(c *store.Client, action string, args ...interface{}) []interface{} {
		t.Helper()
		result, err := c.Execute(ctx, action, args)
		if err != nil || len(result) == 0 {
			t.Fatal("live named verification call failed")
		}
		return result
	}
	success := func(result []interface{}) {
		t.Helper()
		if result[0] != "ok" {
			t.Fatal("live verification operation rejected")
		}
	}
	denied := func(result []interface{}) {
		t.Helper()
		if result[0] == "ok" {
			t.Fatal("expired or already consumed proof accepted")
		}
	}
	now := time.Now().Unix()
	for _, purpose := range []string{"registration", "reset"} {
		t.Run(purpose, func(t *testing.T) {
			email := prefix + "-" + purpose + "@example.test"
			proof, grant := digest(email+"\x00"+"123456"), digest(email+"-grant")
			success(call(first, "code_start", purpose, email, proof, now, digest(email+"-origin"), 20))
			success(call(second, "code_verify", purpose, email, proof, now+599, grant))
			denied(call(first, "code_verify", purpose, email, proof, now+599, digest(email+"-replay")))
			other := "registration"
			if purpose == other {
				other = "reset"
			}
			denied(call(first, "grant_consume", other, email, grant, now+599))
			denied(call(first, "grant_consume", purpose, prefix+"-wrong@example.test", grant, now+599))
			consumed := call(first, "grant_consume", purpose, email, grant, now+1198)
			success(consumed)
			tuple, ok := consumed[1].([]interface{})
			if !ok || len(tuple) != 1 {
				t.Fatal("stored grant expiry absent")
			}
			expiry, ok := directTestUnix(tuple[0])
			if !ok || expiry != now+1199 {
				t.Fatal("grant TTL must be exactly 600 seconds")
			}
			denied(call(second, "grant_consume", purpose, email, grant, now+1198))
		})
		t.Run(purpose+"_code_ttl", func(t *testing.T) {
			email := prefix + "-" + purpose + "-code-ttl@example.test"
			proof := digest(email + "123456")
			success(call(first, "code_start", purpose, email, proof, now, digest(email), 20))
			denied(call(second, "code_verify", purpose, email, proof, now+600, digest(email+"grant")))
		})
		t.Run(purpose+"_grant_ttl", func(t *testing.T) {
			email := prefix + "-" + purpose + "-grant-ttl@example.test"
			proof, grant := digest(email+"123456"), digest(email+"grant")
			success(call(first, "code_start", purpose, email, proof, now, digest(email), 20))
			success(call(second, "code_verify", purpose, email, proof, now, grant))
			denied(call(first, "grant_consume", purpose, email, grant, now+600))
		})
	}
}
