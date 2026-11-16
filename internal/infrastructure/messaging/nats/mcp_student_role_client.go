package natsadapter

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/example/auth-service/internal/domain"
)

const (
	mcpStudentRoleSubject           = "rbac.checkMCPStudentRole"
	maxMCPStudentRoleRequestBytes  = 9 << 10
	mcpStudentRoleRequestTimeout   = 3 * time.Second
)

// mcpStudentRoleClient is source-only: neither bootstrap nor token exchange
// constructs it. It cannot be redirected to legacy unsigned role RPCs.
type mcpStudentRoleClient struct {
	conn                permissionNATSRequester
	decisionVerifier    *mcpStudentRoleDecisionVerifier
	decisionVerifierErr error
}

// NewMCPStudentRoleClient consumes only dedicated RBAC-signed role decisions.
// Missing or invalid key configuration makes all calls fail closed.
func NewMCPStudentRoleClient(conn *nats.Conn, decisionPublicKeyPEM string) domain.MCPStudentRoleDecisionClient {
	verifier, err := newMCPStudentRoleDecisionVerifier(decisionPublicKeyPEM)
	var requester permissionNATSRequester
	if conn != nil {
		requester = conn
	}
	return &mcpStudentRoleClient{conn: requester, decisionVerifier: verifier, decisionVerifierErr: err}
}

func (c *mcpStudentRoleClient) CheckMCPStudentRole(ctx context.Context, proof, expectedStudentID, requestJTI string) (bool, error) {
	if c == nil || c.conn == nil || c.decisionVerifierErr != nil || c.decisionVerifier == nil ||
		ctx == nil || ctx.Err() != nil || proof == "" ||
		!validNonZeroCanonicalReviewerUUID(expectedStudentID) ||
		!validNonZeroCanonicalReviewerUUID(requestJTI) {
		return false, errors.New("MCP Student role lookup unavailable")
	}
	request, err := json.Marshal(rbacPermissionCheckRequest{Proof: proof})
	if err != nil || len(request) > maxMCPStudentRoleRequestBytes {
		return false, errors.New("MCP Student role request invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, mcpStudentRoleRequestTimeout)
	defer cancel()
	msg, err := c.conn.RequestWithContext(ctx, mcpStudentRoleSubject, request)
	if err != nil {
		return false, errors.New("MCP Student role lookup unavailable")
	}
	if msg == nil || len(msg.Data) == 0 || len(msg.Data) > maxMCPStudentRoleDecisionJWTBytes+128 {
		return false, errors.New("MCP Student role decision reply invalid")
	}
	var response struct {
		DecisionJWT string `json:"decision_jwt"`
	}
	if strictReviewerDecisionJSON(msg.Data, []string{"decision_jwt"}, &response) != nil || response.DecisionJWT == "" {
		return false, errors.New("MCP Student role decision reply unsigned or malformed")
	}
	return c.decisionVerifier.verify(response.DecisionJWT, proof, expectedStudentID, requestJTI)
}
