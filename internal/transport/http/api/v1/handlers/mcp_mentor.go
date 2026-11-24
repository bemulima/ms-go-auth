package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

type MCPMentorOAuthService interface {
	Preview(context.Context, usecase.MCPMentorAuthorizationRequest, string) (*usecase.MCPMentorConsentPreview, error)
	Approve(context.Context, usecase.MCPMentorAuthorizationRequest, string) (string, error)
	Exchange(context.Context, usecase.MCPExternalTokenRequest) (*usecase.MCPMentorTokenResponse, error)
	Revoke(context.Context, string, string, string) error
}
type MCPMentorHandler struct {
	OAuth               MCPMentorOAuthService
	Sessions            usecase.MentorSessionVerifier
	Resource, ConsentUI string
}

func (h MCPMentorHandler) Validate() error {
	u, err := url.Parse(h.ConsentUI)
	if h.OAuth == nil || h.Sessions == nil || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "/mentor/mcp/consent" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != h.ConsentUI {
		return domain.ErrMCPMentorUnavailable
	}
	return nil
}
func mcpMentorHeaders(c echo.Context) {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
}
func mcpMentorError(c echo.Context, status int, code string) error {
	return c.JSON(status, map[string]string{"error": code})
}
func mcpMentorAuthorityError(c echo.Context, err error, token bool) error {
	if err == domain.ErrMCPMentorDenied || err == domain.ErrNotFound {
		if token {
			return mcpMentorError(c, 400, "invalid_grant")
		}
		return mcpMentorError(c, 403, "access_denied")
	}
	return mcpMentorError(c, 503, "temporarily_unavailable")
}
func (h MCPMentorHandler) session(ctx context.Context, c echo.Context) (string, string, error) {
	values := c.Request().Header.Values("Authorization")
	if h.Sessions == nil {
		return "", "", usecase.ErrMentorSessionUnavailable
	}
	if len(values) != 1 || len(c.Request().Header.Values("Cookie")) != 0 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) > 8199 {
		return "", "", usecase.ErrMentorSessionUnauthenticated
	}
	bearer := strings.TrimPrefix(values[0], "Bearer ")
	if bearer == "" || strings.ContainsAny(bearer, " \t\r\n") {
		return "", "", usecase.ErrMentorSessionUnauthenticated
	}
	result, err := h.Sessions.VerifyToken(ctx, "", bearer)
	if err != nil {
		return "", "", err
	}
	if result == nil || result.UserID == "" {
		return "", "", usecase.ErrMentorSessionUnauthenticated
	}
	return result.UserID, bearer, nil
}
func mcpMentorSessionError(c echo.Context, err error) error {
	if err == usecase.ErrMentorSessionUnauthenticated {
		return mcpMentorError(c, 401, "invalid_token")
	}
	return mcpMentorError(c, 503, "temporarily_unavailable")
}
func (h MCPMentorHandler) recheck(ctx context.Context, subject, bearer string) error {
	current, err := h.Sessions.VerifyToken(ctx, "", bearer)
	if err != nil {
		return err
	}
	if current == nil || current.UserID != subject {
		return usecase.ErrMentorSessionUnauthenticated
	}
	return nil
}
func (h MCPMentorHandler) Authorize(c echo.Context) error {
	mcpMentorHeaders(c)
	fields, err := mcpMentorQuery(c.Request().URL.RawQuery, mcpBrowserFields)
	if err != nil || h.Validate() != nil || !usecase.ValidMCPMentorAuthorizationRequest(mcpMentorRequest(fields), h.Resource) {
		return mcpMentorError(c, 400, "invalid_request")
	}
	page, _ := url.Parse(h.ConsentUI)
	values := url.Values{}
	for key, value := range fields {
		values.Set(key, value)
	}
	page.RawQuery = values.Encode()
	return c.Redirect(http.StatusFound, page.String())
}
func (h MCPMentorHandler) Consent(c echo.Context) error {
	mcpMentorHeaders(c)
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()
	subject, bearer, err := h.session(ctx, c)
	if err != nil {
		return mcpMentorSessionError(c, err)
	}
	var fields map[string]string
	if c.Request().Method == http.MethodGet {
		fields, err = mcpMentorQuery(c.Request().URL.RawQuery, mcpBrowserFields)
	} else {
		if c.Request().URL.RawQuery != "" || !mcpExactContentType(c.Request(), "application/json") {
			return mcpMentorError(c, 400, "invalid_request")
		}
		fields, err = mcpMentorJSONFields(c, 4096, mcpBrowserFields)
	}
	if err != nil || !usecase.ValidMCPMentorAuthorizationRequest(mcpMentorRequest(fields), h.Resource) {
		return mcpMentorError(c, 400, "invalid_request")
	}
	if h.OAuth == nil {
		return mcpMentorError(c, 503, "temporarily_unavailable")
	}
	request := mcpMentorRequest(fields)
	if c.Request().Method == http.MethodGet {
		preview, err := h.OAuth.Preview(ctx, request, subject)
		if err != nil {
			return mcpMentorAuthorityError(c, err, false)
		}
		if err = h.recheck(ctx, subject, bearer); err != nil {
			return mcpMentorSessionError(c, err)
		}
		return c.JSON(200, preview)
	}
	callback, err := h.OAuth.Approve(ctx, request, subject)
	if err != nil {
		return mcpMentorAuthorityError(c, err, false)
	}
	if err = h.recheck(ctx, subject, bearer); err != nil {
		return mcpMentorSessionError(c, err)
	}
	return c.JSON(200, map[string]string{"redirect_uri": callback})
}
func (h MCPMentorHandler) Revoke(c echo.Context) error {
	mcpMentorHeaders(c)
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	if c.Request().URL.RawQuery != "" || !mcpExactContentType(c.Request(), "application/json") {
		return mcpMentorError(c, 400, "invalid_request")
	}
	subject, _, err := h.session(ctx, c)
	if err != nil {
		return mcpMentorSessionError(c, err)
	}
	fields, err := mcpMentorJSONFields(c, 4096, []string{"client_id", "resource"})
	if err != nil || fields["resource"] != h.Resource {
		return mcpMentorError(c, 400, "invalid_request")
	}
	if h.OAuth == nil {
		return mcpMentorError(c, 503, "temporarily_unavailable")
	}
	if err = h.OAuth.Revoke(ctx, subject, fields["client_id"], fields["resource"]); err != nil {
		return mcpMentorAuthorityError(c, err, false)
	}
	return c.NoContent(204)
}
func (h MCPMentorHandler) Token(c echo.Context) error {
	mcpMentorHeaders(c)
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()
	r := c.Request()
	if r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 || !mcpExactContentType(r, "application/x-www-form-urlencoded") {
		return mcpMentorError(c, 400, "invalid_request")
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 8192)
	if r.ParseForm() != nil || len(r.PostForm) != 6 {
		return mcpMentorError(c, 400, "invalid_request")
	}
	for _, name := range []string{"grant_type", "code", "code_verifier", "client_id", "redirect_uri", "resource"} {
		if len(r.PostForm[name]) != 1 || r.PostForm.Get(name) == "" {
			return mcpMentorError(c, 400, "invalid_request")
		}
	}
	if h.OAuth == nil {
		return mcpMentorError(c, 503, "temporarily_unavailable")
	}
	result, err := h.OAuth.Exchange(ctx, usecase.MCPExternalTokenRequest{GrantType: r.PostForm.Get("grant_type"), Code: r.PostForm.Get("code"), Verifier: r.PostForm.Get("code_verifier"), ClientID: r.PostForm.Get("client_id"), RedirectURI: r.PostForm.Get("redirect_uri"), ResourceURI: r.PostForm.Get("resource")})
	if err != nil {
		return mcpMentorAuthorityError(c, err, true)
	}
	return c.JSON(200, result)
}
func mcpMentorRequest(f map[string]string) usecase.MCPMentorAuthorizationRequest {
	return usecase.MCPMentorAuthorizationRequest{ResponseType: f["response_type"], ClientID: f["client_id"], RedirectURI: f["redirect_uri"], Resource: f["resource"], Challenge: f["code_challenge"], ChallengeMethod: f["code_challenge_method"], Scope: f["scope"], State: f["state"]}
}
func mcpMentorQuery(raw string, names []string) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, domain.ErrMCPMentorDenied
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) != len(names) {
		return nil, domain.ErrMCPMentorDenied
	}
	result := map[string]string{}
	for _, key := range names {
		v := values[key]
		if len(v) != 1 || len(v[0]) == 0 || len(v[0]) > 2048 || strings.ContainsAny(v[0], "\r\n\x00") || !utf8.ValidString(v[0]) {
			return nil, domain.ErrMCPMentorDenied
		}
		result[key] = v[0]
	}
	return result, nil
}
func mcpMentorJSONFields(c echo.Context, limit int64, names []string) (map[string]string, error) {
	data, err := io.ReadAll(http.MaxBytesReader(c.Response(), c.Request().Body, limit))
	if err != nil || !utf8.Valid(data) {
		return nil, domain.ErrMCPMentorDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, domain.ErrMCPMentorDenied
	}
	allowed := map[string]bool{}
	for _, key := range names {
		allowed[key] = true
	}
	result := map[string]string{}
	for d.More() {
		start := d.InputOffset()
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || result[key] != "" || string(bytes.TrimLeft(data[start:d.InputOffset()], ", \t\r\n")) != "\""+key+"\"" {
			return nil, domain.ErrMCPMentorDenied
		}
		var value string
		if d.Decode(&value) != nil || value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return nil, domain.ErrMCPMentorDenied
		}
		result[key] = value
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(result) != len(names) || d.Decode(new(any)) != io.EOF {
		return nil, domain.ErrMCPMentorDenied
	}
	return result, nil
}
