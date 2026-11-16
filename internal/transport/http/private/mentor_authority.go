package internalhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/usecase"
)

const (
	MentorSessionVerifyPath      = "/internal/v1/mentor/session/verify"
	MentorAdminSessionVerifyPath = "/internal/v1/mentor/admin-session/verify"
	MentorRoleDecisionPath       = "/internal/v1/mentor/role-decisions"
	mentorHTTPBodyLimit          = 16384
)

type MentorHTTPAuthorityHandler struct{ authority *usecase.MentorHTTPAuthority }

func NewMentorHTTPAuthorityHandler(authority *usecase.MentorHTTPAuthority) (*MentorHTTPAuthorityHandler, error) {
	if !authority.Configured() {
		return nil, usecase.ErrMentorSessionUnavailable
	}
	return &MentorHTTPAuthorityHandler{authority: authority}, nil
}

// ServeHTTP implements only the three fixed source-contract paths. It is not
// registered by the existing router or composition root. No caller identity,
// role, trace or middleware context value is used as authority.
func (h *MentorHTTPAuthorityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if h == nil || !h.authority.Configured() {
		mentorHTTPFailure(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if r == nil || r.URL == nil {
		mentorHTTPFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	switch r.URL.Path {
	case MentorSessionVerifyPath, MentorAdminSessionVerifyPath, MentorRoleDecisionPath:
	default:
		mentorHTTPFailure(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		mentorHTTPFailure(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if r.TLS == nil || (r.URL.Scheme != "" && r.URL.Scheme != "https") || r.URL.User != nil ||
		r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawFragment != "" {
		mentorHTTPFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	contentType, single := mentorSingleHeader(r.Header, "Content-Type")
	if !single || !mentorJSONContentType(contentType) {
		mentorHTTPFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	authorization, single := mentorSingleHeader(r.Header, "Authorization")
	if !single || len(authorization) < 8 || len(authorization) > domain.MentorSessionMaxTokenBytes+7 ||
		!strings.EqualFold(authorization[:6], "Bearer") || authorization[6] != ' ' ||
		!domain.ValidMentorAccessToken(authorization[7:]) {
		mentorHTTPFailure(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if r.Body == nil || r.ContentLength > mentorHTTPBodyLimit {
		mentorHTTPFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), usecase.MentorHTTPOperationTimeout)
	defer cancel()
	if ctx.Err() != nil {
		mentorHTTPFailure(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, mentorHTTPBodyLimit+1))
	if ctx.Err() != nil {
		mentorHTTPFailure(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	request, valid := decodeMentorHTTPRequest(raw, r.URL.Path == MentorRoleDecisionPath)
	if err != nil || len(raw) > mentorHTTPBodyLimit || !valid {
		mentorHTTPFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	bearer := authorization[7:]
	var value, field string
	switch r.URL.Path {
	case MentorSessionVerifyPath:
		value, err = h.authority.VerifyUser(ctx, bearer)
		field = "user_id"
	case MentorAdminSessionVerifyPath:
		value, err = h.authority.VerifyAdmin(ctx, bearer)
		field = "user_id"
	case MentorRoleDecisionPath:
		value, err = h.authority.Issue(ctx, bearer, request)
		field = "proof"
	}
	if ctx.Err() != nil {
		mentorHTTPFailure(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if err != nil || value == "" {
		switch err {
		case usecase.ErrMentorRoleDecisionInvalid:
			mentorHTTPFailure(w, http.StatusBadRequest, "invalid_request")
		case usecase.ErrMentorSessionUnauthenticated:
			mentorHTTPFailure(w, http.StatusUnauthorized, "unauthenticated")
		case usecase.ErrMentorIdentityForbidden, usecase.ErrMentorRoleDecisionDenied:
			mentorHTTPFailure(w, http.StatusForbidden, "forbidden")
		default:
			mentorHTTPFailure(w, http.StatusServiceUnavailable, "unavailable")
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{field: value})
}

func mentorJSONContentType(value string) bool {
	// ParseMediaType silently combines duplicate identical parameters and MIME
	// extended continuations. The owner contract permits only one plain charset
	// parameter, so validate its framing before trusting the normalized map.
	parts := strings.Split(value, ";")
	if len(parts) > 2 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" || len(parameters) != len(parts)-1 {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	name, _, present := strings.Cut(parts[1], "=")
	return present && strings.EqualFold(strings.TrimSpace(name), "charset") &&
		strings.EqualFold(parameters["charset"], "utf-8")
}

func mentorSingleHeader(header http.Header, key string) (string, bool) {
	count := 0
	var value string
	for name, values := range header {
		if strings.EqualFold(name, key) {
			count += len(values)
			if len(values) == 1 {
				value = values[0]
			}
		}
	}
	return value, count == 1 && value != ""
}

func mentorHTTPFailure(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func decodeMentorHTTPRequest(raw []byte, issuance bool) (domain.MentorRoleDecisionRequest, bool) {
	var result domain.MentorRoleDecisionRequest
	if len(raw) > mentorHTTPBodyLimit || !validMentorHTTPJSONEncoding(raw) {
		return result, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return result, false
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !issuance {
			return result, false
		}
		switch name {
		case "target_user_id", "application_id", "application_revision", "decision", "request_id", "decision_digest":
		default:
			return result, false
		}
		if _, duplicate := fields[name]; duplicate {
			return result, false
		}
		var field json.RawMessage
		if decoder.Decode(&field) != nil || len(field) == 0 {
			return result, false
		}
		fields[name] = field
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return result, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return result, false
	}
	if !issuance {
		return result, len(fields) == 0
	}
	if len(fields) != 6 {
		return result, false
	}
	for key, target := range map[string]*string{
		"target_user_id": &result.TargetUserID, "application_id": &result.ApplicationID,
		"decision": &result.Decision, "request_id": &result.RequestID, "decision_digest": &result.DecisionDigest,
	} {
		field := fields[key]
		if len(field) == 0 || field[0] != '"' || json.Unmarshal(field, target) != nil {
			return domain.MentorRoleDecisionRequest{}, false
		}
	}
	revision := string(fields["application_revision"])
	for i := range revision {
		if revision[i] < '0' || revision[i] > '9' {
			return domain.MentorRoleDecisionRequest{}, false
		}
	}
	result.ApplicationRevision, err = strconv.ParseInt(revision, 10, 64)
	if err != nil || strconv.FormatInt(result.ApplicationRevision, 10) != revision {
		return domain.MentorRoleDecisionRequest{}, false
	}
	return result, true
}

// encoding/json repairs invalid UTF-8 and unpaired surrogate escapes. Reject
// lossy encodings before decoding exact business identities and property names.
func validMentorHTTPJSONEncoding(raw []byte) bool {
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
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
