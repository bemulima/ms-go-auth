package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/example/auth-service/internal/domain"
)

type MCPMentorApprovalClient struct {
	endpoint, capability string
	client               *http.Client
}

func NewMCPMentorApprovalClient(endpoint, capability string, trustedCAPEM ...string) (*MCPMentorApprovalClient, error) {
	u, err := url.Parse(endpoint)
	for _, b := range []byte(endpoint) {
		if b < 33 || b > 126 || b == '\\' {
			return nil, domain.ErrMCPMentorUnavailable
		}
	}
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/internal/mcp/v1/mentor/approval" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != endpoint || len(endpoint) > 2048 || len(capability) < 32 || len(capability) > 256 || strings.Contains(strings.ToLower(capability), "change-me") || strings.Contains(capability, "${") {
		return nil, domain.ErrMCPMentorUnavailable
	}
	for _, b := range []byte(capability) {
		if b < 33 || b > 126 || b == ',' {
			return nil, domain.ErrMCPMentorUnavailable
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(trustedCAPEM) > 1 {
		return nil, domain.ErrMCPMentorUnavailable
	}
	if len(trustedCAPEM) == 1 && trustedCAPEM[0] != "" {
		remaining := []byte(trustedCAPEM[0])
		if len(remaining) > 65536 {
			return nil, domain.ErrMCPMentorUnavailable
		}
		roots := x509.NewCertPool()
		count := 0
		for len(bytes.TrimSpace(remaining)) > 0 {
			remaining = bytes.TrimSpace(remaining)
			if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, domain.ErrMCPMentorUnavailable
			}
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, domain.ErrMCPMentorUnavailable
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil || !certificate.IsCA {
				return nil, domain.ErrMCPMentorUnavailable
			}
			roots.AddCert(certificate)
			remaining = rest
			count++
		}
		if count == 0 {
			return nil, domain.ErrMCPMentorUnavailable
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 8192, MaxIdleConnsPerHost: 4}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &MCPMentorApprovalClient{endpoint: endpoint, capability: capability, client: client}, nil
}
func (c *MCPMentorApprovalClient) Approved(ctx context.Context, proof, subject string) error {
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil || len(proof) == 0 || len(proof) > 8192 {
		return domain.ErrMCPMentorUnavailable
	}
	body, _ := json.Marshal(struct {
		Proof string `json:"proof"`
	}{proof})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return domain.ErrMCPMentorUnavailable
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MCP-Service-Token", c.capability)
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return domain.ErrMCPMentorUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return domain.ErrMCPMentorDenied
	}
	if response.StatusCode != http.StatusOK {
		return domain.ErrMCPMentorUnavailable
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return domain.ErrMCPMentorUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	if err != nil || len(data) > 2048 || !utf8.Valid(data) || ctx.Err() != nil {
		return domain.ErrMCPMentorUnavailable
	}
	var result struct {
		Schema   string `json:"schema"`
		MentorID string `json:"mentor_id"`
		Approved bool   `json:"approved"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return domain.ErrMCPMentorUnavailable
	}
	seen := map[string]bool{}
	for d.More() {
		start := d.InputOffset()
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || (key != "schema" && key != "mentor_id" && key != "approved") || seen[key] || string(bytes.TrimLeft(data[start:d.InputOffset()], ", \t\r\n")) != "\""+key+"\"" {
			return domain.ErrMCPMentorUnavailable
		}
		seen[key] = true
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return domain.ErrMCPMentorUnavailable
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || len(seen) != 3 || d.Decode(new(any)) != io.EOF || json.Unmarshal(data, &result) != nil || result.Schema != "mentor-mcp-approval.v1" || result.MentorID != subject || !result.Approved {
		return domain.ErrMCPMentorUnavailable
	}
	return nil
}
