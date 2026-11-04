package handlers

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

type reviewerIssuerFunc func(context.Context, string, string, string) (string, error)

func (f reviewerIssuerFunc) Issue(ctx context.Context, actor, decision, digest string) (string, error) {
	return f(ctx, actor, decision, digest)
}

func TestKnowledgeReviewerEndpointUsesAuthenticatedActorAndExactPayload(t *testing.T) {
	const actor = "11111111-1111-4111-8111-111111111111"
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	called := false
	handler := NewAuthHandler(nil, reviewerIssuerFunc(func(_ context.Context, gotActor, decision, gotDigest string) (string, error) {
		called = true
		if gotActor != actor || decision != "APPROVE" || gotDigest != digest {
			t.Fatalf("issuer input = (%q, %q, %q)", gotActor, decision, gotDigest)
		}
		return "synthetic-signed-token", nil
	}))
	e := echo.New()
	req := httptest.NewRequest("POST", "/api/v1/auth/knowledge-graph/reviewer-token", strings.NewReader(`{"decision":"APPROVE","review_binding_digest":"`+digest+`"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.Set("user_id", actor)
	if err := handler.IssueKnowledgeReviewerToken(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || !called || !strings.Contains(rec.Body.String(), "synthetic-signed-token") {
		t.Fatalf("response code=%d called=%v body=%s", rec.Code, called, rec.Body.String())
	}
}

func TestKnowledgeReviewerEndpointRejectsUnknownFieldsAndStaysDisabledByDefault(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	e := echo.New()
	for _, tc := range []struct {
		name   string
		handle *AuthHandler
		body   string
		want   int
	}{
		{"disabled", NewAuthHandler(nil), `{"decision":"APPROVE","review_binding_digest":"` + digest + `"}`, 503},
		{"unknown field", NewAuthHandler(nil, reviewerIssuerFunc(func(context.Context, string, string, string) (string, error) { return "token", nil })), `{"decision":"APPROVE","review_binding_digest":"` + digest + `","actor":"forged"}`, 400},
		{"duplicate field", NewAuthHandler(nil, reviewerIssuerFunc(func(context.Context, string, string, string) (string, error) { return "token", nil })), `{"decision":"REJECT","decision":"APPROVE","review_binding_digest":"` + digest + `"}`, 400},
		{"null field", NewAuthHandler(nil, reviewerIssuerFunc(func(context.Context, string, string, string) (string, error) { return "token", nil })), `{"decision":null,"review_binding_digest":"` + digest + `"}`, 400},
		{"trailing object", NewAuthHandler(nil, reviewerIssuerFunc(func(context.Context, string, string, string) (string, error) { return "token", nil })), `{"decision":"APPROVE","review_binding_digest":"` + digest + `"}{}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/auth/knowledge-graph/reviewer-token", strings.NewReader(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)
			ctx.Set("user_id", "11111111-1111-4111-8111-111111111111")
			if err := tc.handle.IssueKnowledgeReviewerToken(ctx); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestKnowledgeReviewerEndpointDoesNotAcceptCallerIdentityHeaders(t *testing.T) {
	called := false
	handler := NewAuthHandler(nil, reviewerIssuerFunc(func(_ context.Context, actor, decision, digest string) (string, error) {
		called = true
		return "unexpected-token", nil
	}))
	e := echo.New()
	req := httptest.NewRequest("POST", "/api/v1/auth/knowledge-graph/reviewer-token", strings.NewReader(`{"decision":"APPROVE","review_binding_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("X-User-ID", "11111111-1111-4111-8111-111111111111")
	req.Header.Set("X-Role", "admin")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	if err := handler.IssueKnowledgeReviewerToken(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 401 || called {
		t.Fatalf("status=%d issuerCalled=%v body=%s, want 401 without issuance", rec.Code, called, rec.Body.String())
	}
}
