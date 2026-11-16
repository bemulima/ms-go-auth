package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

// MCPExternalCodeIssuer is a separate, opt-in authorization-code completion
// seam. The Student identity comes solely from Auth's verified access session.
type MCPExternalCodeIssuer interface {
	Authorize(context.Context, usecase.MCPExternalAuthorizationRequest, string, string, time.Time) (string, error)
}

type MCPExternalAccessTokenIssuer interface {
	Prepare(context.Context, usecase.MCPExternalTokenRequest, time.Time) (*usecase.MCPExternalAccessTokenIntent, error)
}

type MCPExternalJWTSigner interface {
	Sign(*usecase.MCPExternalAccessTokenIntent) (string, error)
}

type MCPExternalOAuthHandler struct {
	Codes    MCPExternalCodeIssuer
	Tokens   MCPExternalAccessTokenIssuer
	Signer   MCPExternalJWTSigner
	Revoker  domain.MCPExternalConsentRevoker
	Resource string
}

// RevokeConsent is a Student-owned disconnect operation. It invalidates every
// previously issued access token through Auth's fresh grant readback; no
// caller-supplied Student ID, consent ID or OAuth token is accepted.
func (h MCPExternalOAuthHandler) RevokeConsent(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	if h.Revoker == nil || !mcpExactContentType(c.Request(), "application/json") ||
		c.QueryString() != "" || len(c.Request().Header.Values("Authorization")) != 1 ||
		len(c.Request().Header.Values("Cookie")) != 0 {
		return c.NoContent(http.StatusBadRequest)
	}
	student, ok := c.Get("user_id").(string)
	if !ok || student == "" {
		return c.NoContent(http.StatusUnauthorized)
	}
	fields, err := mcpExactStringFields(c, 2048, []string{"client_id", "resource"})
	if err != nil || fields["resource"] != h.Resource {
		return c.NoContent(http.StatusBadRequest)
	}
	if err := h.Revoker.RevokeMCPExternalConsent(c.Request().Context(), student, fields["client_id"], fields["resource"]); err != nil {
		return c.NoContent(http.StatusServiceUnavailable)
	}
	return c.NoContent(http.StatusNoContent)
}

// CompleteAuthorization is a first-party, bearer-authenticated consent
// completion API for a Codechuman BFF/UI. It is NOT a third-party OAuth GET
// authorization endpoint: discovery stays disabled until that browser UI is
// implemented. The client must validate its own nonempty CSRF state on return.
func (h MCPExternalOAuthHandler) CompleteAuthorization(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	if h.Codes == nil || !mcpExactContentType(c.Request(), "application/json") || c.QueryString() != "" ||
		len(c.Request().Header.Values("Authorization")) != 1 ||
		len(c.Request().Header.Values("Cookie")) != 0 {
		return c.NoContent(http.StatusBadRequest)
	}
	studentID, ok := c.Get("user_id").(string)
	if !ok || studentID == "" {
		return c.NoContent(http.StatusUnauthorized)
	}
	fields, err := mcpExactStringFields(c, 4096, []string{
		"response_type", "client_id", "redirect_uri", "resource", "code_challenge",
		"code_challenge_method", "scope", "state",
	})
	if err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	callback, err := h.Codes.Authorize(c.Request().Context(), usecase.MCPExternalAuthorizationRequest{
		ResponseType: fields["response_type"], ClientID: fields["client_id"],
		RedirectURI: fields["redirect_uri"], ResourceURI: fields["resource"],
		CodeChallenge: fields["code_challenge"], CodeChallengeMethod: fields["code_challenge_method"],
		Scope: fields["scope"],
	}, studentID, fields["state"], time.Now().UTC())
	if err != nil || callback == "" {
		return c.NoContent(http.StatusForbidden)
	}
	return c.JSON(http.StatusOK, map[string]string{"redirect_to": callback})
}

// ExchangeToken accepts a public PKCE-S256 OAuth code. The code is atomically
// burned before a fresh RBAC check. This route never accepts an ordinary
// Codechuman frontend JWT, and never issues refresh tokens.
func (h MCPExternalOAuthHandler) ExchangeToken(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	if h.Tokens == nil || h.Signer == nil || c.QueryString() != "" ||
		!mcpExactContentType(c.Request(), "application/x-www-form-urlencoded") ||
		len(c.Request().Header.Values("Authorization")) != 0 ||
		len(c.Request().Header.Values("Cookie")) != 0 {
		return c.NoContent(http.StatusBadRequest)
	}
	// Parsing into url.Values is only safe after duplicate and unknown fields
	// are rejected. The body limit also bounds submitted code/verifier values.
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 8192)
	if err := c.Request().ParseForm(); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	allowed := map[string]bool{
		"grant_type": true, "code": true, "code_verifier": true,
		"client_id": true, "redirect_uri": true, "resource": true,
	}
	values := c.Request().PostForm
	if len(values) != len(allowed) {
		return c.NoContent(http.StatusBadRequest)
	}
	for key, list := range values {
		if !allowed[key] || len(list) != 1 || list[0] == "" || len(list[0]) > 2048 {
			return c.NoContent(http.StatusBadRequest)
		}
	}
	issuedAt := time.Now().UTC()
	intent, err := h.Tokens.Prepare(c.Request().Context(), usecase.MCPExternalTokenRequest{
		GrantType: values.Get("grant_type"), Code: values.Get("code"),
		Verifier: values.Get("code_verifier"), ClientID: values.Get("client_id"),
		RedirectURI: values.Get("redirect_uri"), ResourceURI: values.Get("resource"),
	}, issuedAt)
	if err != nil || intent == nil {
		return c.NoContent(http.StatusBadRequest)
	}
	access, err := h.Signer.Sign(intent)
	if err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	return c.JSON(http.StatusOK, struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}{access, "Bearer", intent.ExpiresAt - issuedAt.Unix(), intent.Scope})
}

func mcpExactContentType(req *http.Request, wanted string) bool {
	values := req.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != wanted {
		return false
	}
	return len(parameters) == 0 ||
		(len(parameters) == 1 && strings.EqualFold(parameters["charset"], "utf-8"))
}

func mcpExactStringFields(c echo.Context, limit int64, names []string) (map[string]string, error) {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	data, err := io.ReadAll(http.MaxBytesReader(c.Response(), c.Request().Body, limit))
	if err != nil || len(data) == 0 || !json.Valid(data) {
		return nil, errors.New("invalid MCP request")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid MCP object")
	}
	fields := make(map[string]string, len(names))
	for dec.More() {
		token, err := dec.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] {
			return nil, errors.New("unknown MCP field")
		}
		if _, present := fields[key]; present {
			return nil, errors.New("duplicate MCP field")
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil || len(raw) == 0 || raw[0] != '"' {
			return nil, errors.New("invalid MCP field")
		}
		var value string
		if json.Unmarshal(raw, &value) != nil || value == "" || strings.ContainsRune(value, 0) {
			return nil, errors.New("invalid MCP value")
		}
		fields[key] = value
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') || len(fields) != len(names) {
		return nil, errors.New("incomplete MCP object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing MCP data")
	}
	return fields, nil
}
