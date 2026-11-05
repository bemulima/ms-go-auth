package usecase

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

const (
	knowledgeReviewerAudience        = "planner-knowledge-review"
	knowledgeReviewerType            = "knowledge_graph_reviewer"
	knowledgeReviewerPerm            = domain.KnowledgeGraphReviewPermission
	knowledgeReviewerTokenTTL        = 90 * time.Second
	knowledgePermissionProofAudience = "ms-go-rbac-knowledge-review"
	knowledgePermissionProofType     = "knowledge_graph_permission_check"
	knowledgePermissionProofPurpose  = "AUTH_RBAC_KNOWLEDGE_GRAPH_REVIEW_PERMISSION_V1"
	knowledgePermissionProofTTL      = 30 * time.Second
	maximumReviewerDigestBytes       = 64
)

var (
	ErrKnowledgeReviewerDenied      = errors.New("knowledge reviewer permission denied")
	ErrKnowledgeReviewerUnavailable = errors.New("knowledge reviewer authority unavailable")
)

// KnowledgeReviewerTokenIssuer mints a short-lived, review-context-bound JWT
// only after the RBAC owner confirms the review permission for the actor.
type KnowledgeReviewerTokenIssuer struct {
	issuer string
	key    *rsa.PrivateKey
	rbac   domain.PermissionChecker
	clock  func() time.Time
}

func NewKnowledgeReviewerTokenIssuer(issuer, privateKeyPEM, publicKeyPEM string, rbac domain.PermissionChecker) (*KnowledgeReviewerTokenIssuer, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" || rbac == nil {
		return nil, ErrKnowledgeReviewerUnavailable
	}
	if strings.TrimSpace(privateKeyPEM) == "" || strings.TrimSpace(publicKeyPEM) == "" {
		return nil, nil // feature remains disabled unless Auth has a matched RSA key pair.
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil || key.N.BitLen() < 2048 {
		return nil, ErrKnowledgeReviewerUnavailable
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPEM))
	if err != nil || publicKey.N.Cmp(key.N) != 0 || publicKey.E != key.E {
		return nil, ErrKnowledgeReviewerUnavailable
	}
	return &KnowledgeReviewerTokenIssuer{issuer: issuer, key: key, rbac: rbac, clock: time.Now}, nil
}

func (issuer *KnowledgeReviewerTokenIssuer) Issue(ctx context.Context, actorID, decision, bindingDigest string) (string, error) {
	return issuer.issue(ctx, actorID, decision, bindingDigest, false)
}

// IssueV2 authorizes the additive asynchronous review lifecycle.
func (issuer *KnowledgeReviewerTokenIssuer) IssueV2(ctx context.Context, actorID, decision, bindingDigest string) (string, error) {
	return issuer.issue(ctx, actorID, decision, bindingDigest, true)
}

func (issuer *KnowledgeReviewerTokenIssuer) issue(ctx context.Context, actorID, decision, bindingDigest string, lifecycleV2 bool) (string, error) {
	if issuer == nil || issuer.key == nil || issuer.rbac == nil || !canonicalReviewerUUID(actorID) ||
		(decision != "APPROVE" && decision != "REJECT" && (!lifecycleV2 || decision != "NEEDS_REVISION")) || !canonicalReviewerDigest(bindingDigest) {
		return "", ErrKnowledgeReviewerUnavailable
	}
	proof, proofJTI, err := issuer.signKnowledgePermissionProof(actorID)
	if err != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	allowed, err := issuer.rbac.HasPermission(ctx, proof, actorID, proofJTI)
	if err != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	if !allowed {
		return "", ErrKnowledgeReviewerDenied
	}
	jti, err := GenerateJTI()
	if err != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	now := issuer.clock().UTC().Truncate(time.Second)
	claims := jwt.MapClaims{
		"iss": issuer.issuer, "aud": knowledgeReviewerAudience, "sub": actorID,
		"iat": now.Unix(), "exp": now.Add(knowledgeReviewerTokenTTL).Unix(),
		"jti": jti, "typ": knowledgeReviewerType, "permission": knowledgeReviewerPerm,
		"decision": decision, "review_binding_digest": bindingDigest,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "JWT"
	signed, err := token.SignedString(issuer.key)
	if err != nil {
		return "", ErrKnowledgeReviewerUnavailable
	}
	return signed, nil
}

func (issuer *KnowledgeReviewerTokenIssuer) signKnowledgePermissionProof(actorID string) (string, string, error) {
	jti, err := GenerateJTI()
	if err != nil {
		return "", "", err
	}
	now := issuer.clock().UTC().Truncate(time.Second)
	claims := jwt.MapClaims{
		"iss": issuer.issuer, "aud": knowledgePermissionProofAudience, "sub": actorID,
		"typ": knowledgePermissionProofType, "purpose": knowledgePermissionProofPurpose,
		"permission": knowledgeReviewerPerm, "jti": jti,
		"iat": now.Unix(), "exp": now.Add(knowledgePermissionProofTTL).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "JWT"
	signed, err := token.SignedString(issuer.key)
	return signed, jti, err
}

func canonicalReviewerUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}

func canonicalReviewerDigest(value string) bool {
	if len(value) != maximumReviewerDigestBytes || value != strings.ToLower(value) {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}
