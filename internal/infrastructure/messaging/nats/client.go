package natsadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/example/auth-service/internal/domain"
)

type userClient struct {
	conn    *nats.Conn
	subject string
}

type rbacClient struct {
	conn             *nats.Conn
	assignSubject    string
	checkRoleSubject string
	signupProof      *signupProofSigner
}

type rbacPermissionClient struct {
	conn                permissionNATSRequester
	subject             string
	decisionVerifier    *reviewerPermissionDecisionVerifier
	decisionVerifierErr error
}

type permissionNATSRequester interface {
	RequestWithContext(context.Context, string, []byte) (*nats.Msg, error)
}

type rbacPermissionCheckRequest struct {
	Proof string `json:"proof"`
}

func NewUserClient(conn *nats.Conn, subject string) domain.UserProvisioner {
	return &userClient{conn: conn, subject: subject}
}

func NewRBACClient(conn *nats.Conn, assignSubject, checkRoleSubject string) domain.RoleClient {
	return &rbacClient{conn: conn, assignSubject: assignSubject, checkRoleSubject: checkRoleSubject}
}

func NewRBACPermissionClient(conn *nats.Conn, subject, decisionPublicKeyPEM string) domain.PermissionChecker {
	verifier, err := newReviewerPermissionDecisionVerifier(decisionPublicKeyPEM)
	return &rbacPermissionClient{conn: conn, subject: subject, decisionVerifier: verifier, decisionVerifierErr: err}
}

func (c *rbacPermissionClient) HasPermission(ctx context.Context, proof, expectedSubject, requestJTI string) (bool, error) {
	if c == nil || c.conn == nil || c.subject == "" || proof == "" ||
		c.decisionVerifierErr != nil || c.decisionVerifier == nil ||
		!validNonZeroCanonicalReviewerUUID(expectedSubject) || !validNonZeroCanonicalReviewerUUID(requestJTI) {
		return false, fmt.Errorf("permission lookup unavailable")
	}
	data, err := json.Marshal(rbacPermissionCheckRequest{Proof: proof})
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	msg, err := c.conn.RequestWithContext(ctx, c.subject, data)
	if err != nil {
		return false, err
	}
	if msg == nil || len(msg.Data) == 0 || len(msg.Data) > maxReviewerPermissionDecisionJWTBytes+128 {
		return false, fmt.Errorf("invalid permission decision reply")
	}
	var response struct {
		DecisionJWT string `json:"decision_jwt"`
	}
	if err := strictReviewerDecisionJSON(msg.Data, []string{"decision_jwt"}, &response); err != nil || response.DecisionJWT == "" {
		return false, fmt.Errorf("unsigned or malformed permission decision reply")
	}
	return c.decisionVerifier.verify(response.DecisionJWT, proof, expectedSubject, requestJTI)
}

func (c *userClient) CreateUser(ctx context.Context, request domain.UserProvisionRequest) error {
	return requestAckWithTimeout(ctx, c.conn, c.subject, request, 12*time.Second)
}

func (c *rbacClient) AssignRole(ctx context.Context, userID, role string) error {
	payload := map[string]interface{}{"user_id": userID, "role": role}
	return requestAck(ctx, c.conn, c.assignSubject, payload)
}

func (c *rbacClient) CheckRole(ctx context.Context, userID, role string) (bool, error) {
	payload := map[string]interface{}{"user_id": userID, "role": role}
	return requestBool(ctx, c.conn, c.checkRoleSubject, payload)
}

func requestAck(ctx context.Context, conn *nats.Conn, subject string, payload interface{}) error {
	return requestAckWithTimeout(ctx, conn, subject, payload, 3*time.Second)
}

func requestAckWithTimeout(ctx context.Context, conn *nats.Conn, subject string, payload interface{}, timeout time.Duration) error {
	data, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	msg, err := conn.RequestWithContext(ctx, subject, data)
	if err != nil {
		return err
	}
	if msg == nil {
		return fmt.Errorf("empty response from %s", subject)
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error != "" {
			return fmt.Errorf(resp.Error)
		}
		return fmt.Errorf("request to %s failed", subject)
	}
	return nil
}

func requestBool(ctx context.Context, conn *nats.Conn, subject string, payload interface{}) (bool, error) {
	data, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	msg, err := conn.RequestWithContext(ctx, subject, data)
	if err != nil {
		return false, err
	}
	if msg == nil {
		return false, fmt.Errorf("empty response from %s", subject)
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return false, err
	}
	if resp.Error != "" {
		return false, fmt.Errorf(resp.Error)
	}
	return resp.OK, nil
}
