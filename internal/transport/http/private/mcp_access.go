package internalhttp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/example/auth-service/internal/usecase"
	"github.com/labstack/echo/v4"
)

// MCPAccessVerifier belongs to Auth. Only the MCP adapter, authenticated with
// a distinct server capability, may invoke the narrow introspection route.
type MCPAccessVerifier interface {
	Verify(context.Context, string, string, time.Time) (*usecase.MCPExternalVerifiedGrant, error)
}

func RegisterMCPAccess(g *echo.Group, verifier MCPAccessVerifier, serverCapability, resource string) error {
	if g == nil || verifier == nil || len(serverCapability) < 32 ||
		serverCapability == "change-me" || !strings.HasPrefix(resource, "https://") {
		return errors.New("MCP introspection prerequisites unavailable")
	}
	g.POST("/mcp/verify", func(c echo.Context) error {
		w, r := c.Response().Writer, c.Request()
		w.Header().Set("Cache-Control", "no-store")
		provided := r.Header.Values("X-MCP-Service-Token")
		if len(provided) != 1 || len(provided[0]) != len(serverCapability) ||
			subtle.ConstantTimeCompare([]byte(provided[0]), []byte(serverCapability)) != 1 ||
			r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
			return c.NoContent(http.StatusUnauthorized)
		}
		r.Body = http.MaxBytesReader(w, r.Body, 9<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var req struct {
			Token    string `json:"token"`
			Resource string `json:"resource"`
		}
		if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF ||
			req.Resource != resource || len(req.Token) == 0 || len(req.Token) > 8192 {
			return c.NoContent(http.StatusUnauthorized)
		}
		verified, err := verifier.Verify(r.Context(), req.Token, resource, time.Now().UTC())
		if err != nil || verified == nil {
			return c.NoContent(http.StatusUnauthorized)
		}
		return c.JSON(http.StatusOK, verified)
	})
	return nil
}
