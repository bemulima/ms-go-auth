package repo

import (
	"encoding/json"
	"net/url"
	"strings"
)

// decodeMCPExternalRedirectURIs validates the Auth-owned, pre-registered
// callback list. Redirects have URL syntax and must not use the narrower
// scope-token validator used for allowed_scopes and granted_scopes.
func decodeMCPExternalRedirectURIs(encoded string) ([]string, bool) {
	if len(encoded) == 0 || len(encoded) > 8192 {
		return nil, false
	}
	var redirects []string
	if err := json.Unmarshal([]byte(encoded), &redirects); err != nil || len(redirects) == 0 || len(redirects) > 32 {
		return nil, false
	}
	seen := make(map[string]bool, len(redirects))
	for _, raw := range redirects {
		if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || seen[raw] {
			return nil, false
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed == nil || parsed.Host == "" || parsed.Hostname() == "" ||
			parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" || strings.Contains(raw, "#") {
			return nil, false
		}
		if parsed.Scheme != "https" && (parsed.Scheme != "http" ||
			(parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1")) {
			return nil, false
		}
		for _, reserved := range []string{"code", "state", "error", "access_token"} {
			if _, exists := parsed.Query()[reserved]; exists {
				return nil, false
			}
		}
		seen[raw] = true
	}
	return redirects, true
}
