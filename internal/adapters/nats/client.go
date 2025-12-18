package natsadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	nats "github.com/nats-io/nats.go"
)

type UserClient interface {
	CreateUser(ctx context.Context, userID string, email string, source string, typ string) error
}

type RBACClient interface {
	AssignRole(ctx context.Context, userID, role string) error
}

type userClient struct {
	conn    *nats.Conn
	subject string
}

type rbacClient struct {
	conn    *nats.Conn
	subject string
}

func NewUserClient(conn *nats.Conn, subject string) UserClient {
	return &userClient{conn: conn, subject: subject}
}

func NewRBACClient(conn *nats.Conn, subject string) RBACClient {
	return &rbacClient{conn: conn, subject: subject}
}

func (c *userClient) CreateUser(ctx context.Context, userID string, email string, source string, typ string) error {
	payload := map[string]interface{}{"id": userID, "email": email, "source": source, "type": typ}
	return requestAck(ctx, c.conn, c.subject, payload)
}

func (c *rbacClient) AssignRole(ctx context.Context, userID, role string) error {
	payload := map[string]interface{}{"user_id": userID, "role": role}
	return requestAck(ctx, c.conn, c.subject, payload)
}

func requestAck(ctx context.Context, conn *nats.Conn, subject string, payload interface{}) error {
	data, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
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
