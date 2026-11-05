package usecase

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"time"
	"unicode/utf8"
)

const KnowledgeReviewerReadAudience = "planner-knowledge-review-read"
const KnowledgeReviewerReadType = "knowledge_graph_reviewer_read"

func ValidKnowledgeReviewerReadScope(scope, graph, version string) bool {
	if scope == "queue" {
		return graph == "" && version == ""
	}
	return scope == "version" && strings.HasPrefix(graph, "kgf1:") && canonicalReviewerDigest(strings.TrimPrefix(graph, "kgf1:")) && utf8.ValidString(version) && len(version) > 0 && len(version) <= 64 && version == strings.ToLower(strings.TrimSpace(version)) && !strings.ContainsRune(version, 0)
}

// IssueRead reuses the signed owner permission lookup, but produces a distinct
// read-only assertion which cannot authorize review decisions or publication.
func (i *KnowledgeReviewerTokenIssuer) IssueRead(ctx context.Context, actor, scope, graph, version string) (string, error) {
	if i == nil || i.key == nil || i.rbac == nil || !canonicalReviewerUUID(actor) || !ValidKnowledgeReviewerReadScope(scope, graph, version) {
		return "", ErrKnowledgeReviewerUnavailable
	}
	proof, proofJTI, e := i.signKnowledgePermissionProof(actor)
	if e != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	allowed, e := i.rbac.HasPermission(ctx, proof, actor, proofJTI)
	if e != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	if !allowed {
		return "", ErrKnowledgeReviewerDenied
	}
	jti, e := GenerateJTI()
	if e != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	now := i.clock().UTC().Truncate(time.Second)
	claims := jwt.MapClaims{"iss": i.issuer, "aud": KnowledgeReviewerReadAudience, "typ": KnowledgeReviewerReadType, "sub": actor, "permission": knowledgeReviewerPerm, "scope": scope, "graph_id": graph, "graph_version": version, "iat": now.Unix(), "exp": now.Add(knowledgeReviewerTokenTTL).Unix(), "jti": jti}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "JWT"
	signed, e := token.SignedString(i.key)
	if e != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	return signed, nil
}
