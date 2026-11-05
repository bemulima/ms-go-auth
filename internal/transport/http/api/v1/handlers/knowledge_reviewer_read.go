package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/example/auth-service/internal/usecase"
	res "github.com/example/auth-service/pkg/http"
	"github.com/labstack/echo/v4"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"
)

func (h *AuthHandler) IssueKnowledgeReviewerReadToken(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	issuer, ok := h.reviewerIssuer.(interface {
		IssueRead(context.Context, string, string, string, string) (string, error)
	})
	if !ok {
		return res.ErrorJSON(c, 503, "reviewer_unavailable", "reviewer read unavailable", requestIDFromCtx(c), nil)
	}
	actor, ok := c.Get("user_id").(string)
	if !ok || actor == "" {
		return res.ErrorJSON(c, 401, "unauthorized", "authenticated subject missing", requestIDFromCtx(c), nil)
	}
	fields, e := decodeReviewerReadRequest(http.MaxBytesReader(c.Response(), c.Request().Body, 4096))
	if e != nil {
		return res.ErrorJSON(c, 400, "bad_request", "invalid payload", requestIDFromCtx(c), nil)
	}
	token, e := issuer.IssueRead(c.Request().Context(), actor, fields["scope"], fields["graph_id"], fields["graph_version"])
	if errors.Is(e, usecase.ErrKnowledgeReviewerDenied) {
		return res.ErrorJSON(c, 403, "forbidden", "review permission required", requestIDFromCtx(c), nil)
	}
	if e != nil {
		return res.ErrorJSON(c, 503, "reviewer_unavailable", "reviewer read unavailable", requestIDFromCtx(c), nil)
	}
	return c.JSON(200, map[string]string{"token": token})
}
func decodeReviewerReadRequest(r io.Reader) (map[string]string, error) {
	raw, readErr := io.ReadAll(io.LimitReader(r, 4097))
	if readErr != nil || len(raw) > 4096 || !validReviewerReadJSONEncoding(raw) {
		return nil, errors.New("invalid JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, errors.New("invalid object")
	}
	fields := map[string]string{}
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok || (name != "scope" && name != "graph_id" && name != "graph_version") {
			return nil, errors.New("invalid field")
		}
		if _, ok := fields[name]; ok {
			return nil, errors.New("duplicate field")
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil || len(raw) == 0 || raw[0] != '"' {
			return nil, errors.New("invalid string")
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return nil, errors.New("invalid string")
		}
		fields[name] = value
	}
	if t, e = d.Token(); e != nil || t != json.Delim('}') {
		return nil, errors.New("invalid object")
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing object")
	}
	if !usecase.ValidKnowledgeReviewerReadScope(fields["scope"], fields["graph_id"], fields["graph_version"]) || (fields["scope"] == "queue" && len(fields) != 1) || (fields["scope"] == "version" && len(fields) != 3) {
		return nil, errors.New("invalid scope")
	}
	return fields, nil
}

// encoding/json repairs invalid UTF-8 and unpaired surrogate escapes. Exact
// version identities reject those lossy encodings before token decoding.
func validReviewerReadJSONEncoding(raw []byte) bool {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		code, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
