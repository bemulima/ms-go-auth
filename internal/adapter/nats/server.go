package natsadapter

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	nats "github.com/nats-io/nats.go"
)

type VerifyHandler struct {
	signer    tokenParser
	respondFn func(msg *nats.Msg, resp verifyResponse)
}

type verifyRequest struct {
	Token string `json:"token"`
}

type verifyResponse struct {
	OK     bool           `json:"ok"`
	UserID string         `json:"user_id,omitempty"`
	Email  string         `json:"email,omitempty"`
	Error  string         `json:"error,omitempty"`
	Claims map[string]any `json:"claims,omitempty"`
}

type tokenParser interface {
	Parse(token string) (*jwt.Token, jwt.MapClaims, error)
}

func NewVerifyHandler(signer tokenParser) *VerifyHandler {
	return &VerifyHandler{signer: signer, respondFn: respond}
}

func (h *VerifyHandler) Subscribe(conn *nats.Conn, subject, queue string) error {
	if conn == nil {
		return errors.New("nats connection is nil")
	}
	_, err := conn.QueueSubscribe(subject, queue, h.handle)
	return err
}

func (h *VerifyHandler) handle(msg *nats.Msg) {
	var req verifyRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		h.respondFn(msg, verifyResponse{OK: false, Error: "invalid_payload"})
		return
	}
	tok, claims, err := h.signer.Parse(req.Token)
	if err != nil || tok == nil || !tok.Valid {
		h.respondFn(msg, verifyResponse{OK: false, Error: "invalid_token"})
		return
	}
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil || time.Now().After(exp.Time) {
		h.respondFn(msg, verifyResponse{OK: false, Error: "expired"})
		return
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if sub == "" {
		h.respondFn(msg, verifyResponse{OK: false, Error: "subject_missing"})
		return
	}
	filtered := map[string]any{}
	for k, v := range claims {
		if k == "sub" || k == "email" {
			continue
		}
		filtered[k] = v
	}
	h.respondFn(msg, verifyResponse{OK: true, UserID: sub, Email: email, Claims: filtered})
}

func respond(msg *nats.Msg, resp verifyResponse) {
	data, _ := json.Marshal(resp)
	_ = msg.Respond(data)
}
