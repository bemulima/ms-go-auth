package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
)

var mcpBrowserState = regexp.MustCompile(`^[A-Za-z0-9._~-]{22,256}$`)
var mcpBrowserChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

var mcpBrowserFields = []string{
	"response_type", "client_id", "redirect_uri", "resource",
	"code_challenge", "code_challenge_method", "scope", "state",
}

// mcpBrowserAllowedReadScope follows the explicit MCP-01 Auth/RBAC read ceiling.
// Each browser authorization request selects exactly one read scope; none of
// these scopes bypasses client registration, Student consent or fresh RBAC.
func mcpBrowserAllowedReadScope(scope string) bool {
	switch scope {
	case "courses:read", "profile:read", "tasks:read":
		return true
	default:
		return false
	}
}

// ValidateBrowserUI accepts only an operator-configured first-party HTTPS
// consent page, never an OAuth client's callback or user-supplied redirect.
func (h MCPExternalOAuthHandler) ValidateBrowserUI() error {
	u, err := url.Parse(h.ConsentUIURI)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.Path != "/student/mcp/consent" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || u.Opaque != "" ||
		u.String() != h.ConsentUIURI || h.Resource == "" {
		return errors.New("invalid first-party MCP consent UI URI")
	}
	return nil
}

// StartBrowserAuthorization only sends the non-secret public PKCE request to
// the first-party Student UI. It neither creates consent nor issues a code;
// the authenticated POST completion still rechecks Auth persistence and RBAC.
func (h MCPExternalOAuthHandler) StartBrowserAuthorization(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	if h.ValidateBrowserUI() != nil || c.Request().Method != http.MethodGet ||
		len(c.QueryString()) == 0 || len(c.QueryString()) > 4096 {
		return c.NoContent(http.StatusBadRequest)
	}
	params := c.QueryParams()
	if len(params) != len(mcpBrowserFields) {
		return c.NoContent(http.StatusBadRequest)
	}
	for _, name := range mcpBrowserFields {
		values := params[name]
		if len(values) != 1 || values[0] == "" || len(values[0]) > 2048 ||
			strings.ContainsAny(values[0], "\r\n\x00") {
			return c.NoContent(http.StatusBadRequest)
		}
	}
	if params.Get("response_type") != "code" ||
		params.Get("code_challenge_method") != "S256" ||
		!mcpBrowserAllowedReadScope(params.Get("scope")) ||
		params.Get("resource") != h.Resource ||
		!mcpBrowserState.MatchString(params.Get("state")) ||
		!mcpBrowserChallenge.MatchString(params.Get("code_challenge")) ||
		len(params.Get("client_id")) > 256 || strings.ContainsAny(params.Get("client_id"), " \t") {
		return c.NoContent(http.StatusBadRequest)
	}
	redirect, err := url.Parse(params.Get("redirect_uri"))
	if err != nil || redirect == nil || redirect.Host == "" || redirect.User != nil ||
		redirect.Fragment != "" || redirect.Opaque != "" {
		return c.NoContent(http.StatusBadRequest)
	}
	if redirect.Scheme != "https" && (redirect.Scheme != "http" ||
		(redirect.Hostname() != "localhost" && redirect.Hostname() != "127.0.0.1" && redirect.Hostname() != "::1")) {
		return c.NoContent(http.StatusBadRequest)
	}
	for _, forbidden := range []string{"code", "state", "error", "access_token"} {
		if redirect.Query().Has(forbidden) {
			return c.NoContent(http.StatusBadRequest)
		}
	}
	page, _ := url.Parse(h.ConsentUIURI) // validated before inspecting request
	page.RawQuery = params.Encode()
	return c.Redirect(http.StatusFound, page.String())
}
