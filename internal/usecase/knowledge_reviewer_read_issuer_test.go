package usecase

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"testing"
	"time"
)

func TestReviewerReadAssertionUsesSignedPermissionAndDistinctScope(t *testing.T) {
	key, priv, pub := reviewerKeyPEMs(t)
	actor := "11111111-1111-4111-8111-111111111111"
	rbac := &reviewerPermissionFixture{allowed: true}
	u, e := NewKnowledgeReviewerTokenIssuer("auth.synthetic", priv, pub, rbac)
	if e != nil {
		t.Fatal(e)
	}
	u.clock = func() time.Time { return time.Unix(1800000000, 0) }
	for _, v := range []struct{ scope, graph, version string }{{"queue", "", ""}, {"version", "kgf1:" + strings.Repeat("a", 64), "1"}} {
		raw, e := u.IssueRead(context.Background(), actor, v.scope, v.graph, v.version)
		if e != nil {
			t.Fatal(e)
		}
		c := jwt.MapClaims{}
		if _, e = jwt.ParseWithClaims(raw, c, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithTimeFunc(u.clock), jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(KnowledgeReviewerReadAudience), jwt.WithIssuer("auth.synthetic")); e != nil {
			t.Fatal(e)
		}
		if c["typ"] != KnowledgeReviewerReadType || c["scope"] != v.scope || c["graph_id"] != v.graph || c["graph_version"] != v.version || c["sub"] != actor || c["permission"] != knowledgeReviewerPerm || c["decision"] != nil || c["review_binding_digest"] != nil || c["exp"].(float64)-c["iat"].(float64) != 90 {
			t.Fatal("read assertion claims changed")
		}
		jti, _ := c["jti"].(string)
		if !canonicalReviewerUUID(jti) || jti == rbac.requestJTI || rbac.subject != actor || rbac.proof == "" {
			t.Fatal("read proof identity/JTI missing")
		}
		if _, e = jwt.Parse(raw, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithTimeFunc(u.clock), jwt.WithAudience(knowledgeReviewerAudience)); e == nil {
			t.Fatal("read assertion accepted as write token")
		}
	}
}
func TestReviewerReadDeniesInvalidScopeAndRBACFailure(t *testing.T) {
	_, priv, pub := reviewerKeyPEMs(t)
	actor := "11111111-1111-4111-8111-111111111111"
	for _, v := range []struct{ scope, graph, version string }{{"queue", "kgf1:" + strings.Repeat("a", 64), ""}, {"version", "", "1"}, {"version", "kgf1:" + strings.Repeat("a", 64), "UPPER"}, {"APPROVE", "", ""}} {
		r := &reviewerPermissionFixture{allowed: true}
		u, _ := NewKnowledgeReviewerTokenIssuer("auth.synthetic", priv, pub, r)
		if token, e := u.IssueRead(context.Background(), actor, v.scope, v.graph, v.version); e == nil || token != "" || r.proof != "" {
			t.Fatal("invalid scope used authority")
		}
	}
	for _, r := range []*reviewerPermissionFixture{{allowed: false}, {err: errors.New("synthetic unavailable")}} {
		u, _ := NewKnowledgeReviewerTokenIssuer("auth.synthetic", priv, pub, r)
		if token, e := u.IssueRead(context.Background(), actor, "queue", "", ""); e == nil || token != "" {
			t.Fatal("RBAC failure issued read token")
		}
	}
}
