package handlers

import (
	"context"
	"github.com/labstack/echo/v4"
	"net/http/httptest"
	"strings"
	"testing"
)

type reviewerReadFixture struct{ called bool }

func (f *reviewerReadFixture) Issue(context.Context, string, string, string) (string, error) {
	panic("write issuer must not be used")
}
func (f *reviewerReadFixture) IssueRead(_ context.Context, actor, scope, graph, version string) (string, error) {
	f.called = true
	if actor != "11111111-1111-4111-8111-111111111111" || scope != "queue" || graph != "" || version != "" {
		panic("unexpected read binding")
	}
	return "synthetic-signed-read", nil
}
func TestReviewerReadEndpointStrictQueueAndAuthenticatedActor(t *testing.T) {
	for _, tc := range []struct {
		actor, body string
		want        int
	}{{"11111111-1111-4111-8111-111111111111", `{"scope":"queue"}`, 200}, {"", `{"scope":"queue"}`, 401}, {"11111111-1111-4111-8111-111111111111", `{"scope":"queue","graph_id":""}`, 400}, {"11111111-1111-4111-8111-111111111111", `{"scope":"queue","scope":"queue"}`, 400}, {"11111111-1111-4111-8111-111111111111", `{"scope":"queue","actor":"forged"}`, 400}} {
		f := &reviewerReadFixture{}
		h := NewAuthHandler(nil, f)
		e := echo.New()
		req := httptest.NewRequest("POST", "/api/v1/auth/v2/knowledge-graph/reviewer-read-token", strings.NewReader(tc.body))
		req.Header.Set("X-Role", "admin")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if tc.actor != "" {
			c.Set("user_id", tc.actor)
		}
		if e := h.IssueKnowledgeReviewerReadToken(c); e != nil {
			t.Fatal(e)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("sensitive assertion response cacheable")
		}
		if rec.Code != tc.want || f.called != (tc.want == 200) {
			t.Fatalf("status=%d called=%v", rec.Code, f.called)
		}
	}
}
func TestReviewerReadVersionRequiresExactFields(t *testing.T) {
	valid := `{"scope":"version","graph_id":"kgf1:` + strings.Repeat("a", 64) + `","graph_version":"1"}`
	if _, e := decodeReviewerReadRequest(strings.NewReader(valid)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{`{"scope":"version"}`, `{"scope":null}`, valid + `{}`, `{"scope":"queue","decision":"REJECT"}`} {
		if _, e := decodeReviewerReadRequest(strings.NewReader(bad)); e == nil {
			t.Fatal("invalid scope accepted")
		}
	}
}

func TestReviewerReadRejectsLossyUnicodeVersionAliases(t *testing.T) {
	prefix := `{"scope":"version","graph_id":"kgf1:` + strings.Repeat("a", 64) + `","graph_version":"`
	for _, value := range []string{`\ud800`, `\udc00`, `\ud800x`, string([]byte{0xff})} {
		if _, e := decodeReviewerReadRequest(strings.NewReader(prefix + value + `"}`)); e == nil {
			t.Fatal("lossy version alias accepted")
		}
	}
	for _, value := range []string{`\ud83d\ude00`, `\ufffd`} {
		if _, e := decodeReviewerReadRequest(strings.NewReader(prefix + value + `"}`)); e != nil {
			t.Fatal("valid Unicode version rejected")
		}
	}
}
