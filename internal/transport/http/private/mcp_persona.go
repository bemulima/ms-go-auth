package internalhttp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

type MCPMentorAccessVerifier interface {
	Verify(context.Context, string, string, time.Time) (*usecase.MCPMentorVerifiedGrant, error)
}

// Only used when Mentor is explicitly enabled. The unverified JOSE type is a
// selector, never authority. Each branch MUST perform its full verification;
// a failed branch is terminal and cannot fall through to another persona.
func RegisterMCPPersonaAccess(g *echo.Group, student MCPAccessVerifier, mentor MCPMentorAccessVerifier, capability, resource string) error {
	if g == nil || mentor == nil || !ValidMCPPersonaCapability(capability) || !strings.HasPrefix(resource, "https://") {
		return domain.ErrMCPMentorUnavailable
	}
	g.POST("/mcp/verify", func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		r := c.Request()
		provided := r.Header.Values("X-MCP-Service-Token")
		if len(provided) != 1 || len(provided[0]) != len(capability) || subtle.ConstantTimeCompare([]byte(provided[0]), []byte(capability)) != 1 || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 || r.URL.RawQuery != "" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
			return c.NoContent(401)
		}
		data, err := io.ReadAll(http.MaxBytesReader(c.Response(), r.Body, 9<<10))
		if err != nil || !utf8.Valid(data) {
			return c.NoContent(401)
		}
		fields, err := mcpPersonaRequest(data)
		if err != nil || fields["resource"] != resource || len(fields["token"]) > 8192 {
			return c.NoContent(401)
		}
		parts := strings.Split(fields["token"], ".")
		if len(parts) != 3 {
			return c.NoContent(401)
		}
		header, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
		if err != nil || len(header) > 512 {
			return c.NoContent(401)
		}
		var selector struct {
			Type string `json:"typ"`
		}
		if json.Unmarshal(header, &selector) != nil {
			return c.NoContent(401)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		switch selector.Type {
		case domain.MCPMentorAccessType:
			result, err := mentor.Verify(ctx, fields["token"], resource, time.Now().UTC())
			if err != nil || result == nil {
				return c.NoContent(401)
			}
			return c.JSON(200, result)
		case usecase.MCPExternalAccessTokenJOSEType:
			if student == nil {
				return c.NoContent(401)
			}
			result, err := student.Verify(ctx, fields["token"], resource, time.Now().UTC())
			if err != nil || result == nil {
				return c.NoContent(401)
			}
			return c.JSON(200, result)
		default:
			return c.NoContent(401)
		}
	})
	return nil
}

func ValidMCPPersonaCapability(value string) bool {
	if len(value) < 32 || len(value) > 4096 {
		return false
	}
	for _, bad := range []string{"change-me", "placeholder", "replace-me", "example", "${"} {
		if strings.Contains(strings.ToLower(value), bad) {
			return false
		}
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 || b == ',' {
			return false
		}
	}
	return true
}
func mcpPersonaRequest(data []byte) (map[string]string, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, domain.ErrMCPMentorDenied
	}
	values := map[string]string{}
	for d.More() {
		start := d.InputOffset()
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "token" && key != "resource") || values[key] != "" || string(bytes.TrimLeft(data[start:d.InputOffset()], ", \t\r\n")) != "\""+key+"\"" {
			return nil, domain.ErrMCPMentorDenied
		}
		var value string
		if d.Decode(&value) != nil || value == "" {
			return nil, domain.ErrMCPMentorDenied
		}
		values[key] = value
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(values) != 2 || d.Decode(new(any)) != io.EOF {
		return nil, domain.ErrMCPMentorDenied
	}
	return values, nil
}
