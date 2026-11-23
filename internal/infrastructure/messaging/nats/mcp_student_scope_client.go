package natsadapter

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/example/auth-service/internal/domain"
	nats "github.com/nats-io/nats.go"
)

const (
	mcpStudentScopeSubject          = "rbac.checkMCPStudentScopes"
	maxMCPStudentScopeProofJWTBytes = 8 << 10
	maxMCPStudentScopeRequestBytes  = 9 << 10
	mcpStudentScopeRequestTimeout   = 3 * time.Second
)

// mcpStudentScopeClient is only a dormant outbound request/reply candidate.
// It has no active bootstrap wiring or private NATS subscription.
type mcpStudentScopeClient struct {
	conn                permissionNATSRequester
	decisionVerifier    *mcpStudentScopeDecisionVerifier
	decisionVerifierErr error
}

// NewMCPStudentScopeClient uses a dedicated RBAC scope-decision public key.
// Empty or invalid key configuration never falls back to reviewer/role checks.
func NewMCPStudentScopeClient(conn *nats.Conn, decisionPublicKeyPEM string) domain.MCPStudentScopeDecisionClient {
	verifier, err := newMCPStudentScopeDecisionVerifier(decisionPublicKeyPEM)
	var requester permissionNATSRequester
	if conn != nil {
		requester = conn
	}
	return &mcpStudentScopeClient{conn: requester, decisionVerifier: verifier, decisionVerifierErr: err}
}

func (c *mcpStudentScopeClient) CheckMCPStudentScopes(
	ctx context.Context, proof, expectedStudentID, requestJTI string, requestedScopes []string,
) ([]string, error) {
	if c == nil || c.conn == nil || c.decisionVerifierErr != nil || c.decisionVerifier == nil ||
		ctx == nil || ctx.Err() != nil || proof == "" ||
		len(proof) > maxMCPStudentScopeProofJWTBytes ||
		!validNonZeroCanonicalReviewerUUID(expectedStudentID) ||
		!validNonZeroCanonicalReviewerUUID(requestJTI) ||
		!domain.ValidMCPStudentRequestedScopes(requestedScopes) {
		return nil, errors.New("MCP Student scopes lookup unavailable")
	}
	request, err := json.Marshal(rbacPermissionCheckRequest{Proof: proof})
	if err != nil || len(request) > maxMCPStudentScopeRequestBytes {
		return nil, errors.New("MCP Student scopes request invalid")
	}
	boundCtx, cancel := context.WithTimeout(ctx, mcpStudentScopeRequestTimeout)
	defer cancel()
	msg, err := c.conn.RequestWithContext(boundCtx, mcpStudentScopeSubject, request)
	if err != nil {
		return nil, errors.New("MCP Student scopes lookup unavailable")
	}
	if msg == nil || len(msg.Data) == 0 || len(msg.Data) > maxMCPStudentScopeDecisionJWTBytes+128 {
		return nil, errors.New("MCP Student scopes decision reply invalid")
	}
	var response struct {
		DecisionJWT string `json:"decision_jwt"`
	}
	if strictReviewerDecisionJSON(msg.Data, []string{"decision_jwt"}, &response) != nil || response.DecisionJWT == "" {
		return nil, errors.New("MCP Student scopes decision reply unsigned or malformed")
	}
	return c.decisionVerifier.verify(response.DecisionJWT, proof, expectedStudentID, requestJTI, requestedScopes)
}
