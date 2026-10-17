package c2bfixture

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/example/auth-service/internal/domain"
	"io"
	"os"
	"time"
)

type Marker struct {
	Schema     string    `json:"schema"`
	Project    string    `json:"project"`
	Run        string    `json:"run_id"`
	AuthDB     string    `json:"auth_database"`
	RBACDB     string    `json:"rbac_database"`
	PublicKey  string    `json:"auth_public_key"`
	Instance   string    `json:"task_instance_id"`
	Submission string    `json:"submission_id"`
	Expires    time.Time `json:"expires_at"`
}

func Strict(raw []byte, out any) error {
	if len(raw) > 16384 {
		return errors.New("bounded JSON exceeded")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if v, ok := t.(json.Delim); ok {
			switch v {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] {
						return errors.New("duplicate or invalid key")
					}
					seen[s] = true
					if e = walk(); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e := walk(); e != nil {
						return e
					}
				}
			default:
				return errors.New("invalid delimiter")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func PrivateFile(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("restricted regular file required")
	}
	return os.ReadFile(path)
}
func gateMarker(mode string) (Marker, error) {
	var m Marker
	deny := errors.New("C2-B isolated authority denied")
	runtime := mode == "auth-runtime"
	if (mode == "rbac" && os.Getenv("APP_ENV") != "c2b-proof") || (mode != "rbac" && os.Getenv("AUTH_APP_ENV") != "c2b-proof") {
		return m, errors.New("production environment denied")
	}
	if os.Getenv("C2B_ENV") != "c2b-proof" || (!runtime && os.Getenv("C2B_FIXTURE_ENABLED") != "true") || (runtime && os.Getenv("AUTH_C2B_PROOF_ENABLED") != "true") {
		return m, deny
	}
	raw, e := PrivateFile(os.Getenv("C2B_OWNERSHIP_MARKER"))
	if e != nil || Strict(raw, &m) != nil {
		return m, deny
	}
	if m.Schema != "c2b-proof-ownership.v1" || m.Project != "c2b-proof-20261016" || m.Run != domain.C2BRun || m.AuthDB != "c2b_auth_20261016" || m.RBACDB != "c2b_rbac_20261016" || m.Instance != domain.C2BInstance || m.Submission != domain.C2BSubmission || !m.Expires.After(time.Now()) || m.Expires.After(time.Now().Add(24*time.Hour)) {
		return m, deny
	}
	key, e := base64.StdEncoding.DecodeString(m.PublicKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return m, deny
	}
	return m, nil
}
func Verify(m Marker, s domain.C2BSignedIntent) (domain.C2BIntent, error) {
	var i domain.C2BIntent
	deny := errors.New("bootstrap proof denied")
	pub, e := base64.StdEncoding.DecodeString(m.PublicKey)
	if e != nil || len(pub) != 32 {
		return i, deny
	}
	b, e := base64.StdEncoding.DecodeString(s.Payload)
	if e != nil || base64.StdEncoding.EncodeToString(b) != s.Payload || len(b) > 8192 {
		return i, deny
	}
	sig, e := base64.StdEncoding.DecodeString(s.Signature)
	if e != nil || len(sig) != 64 || !ed25519.Verify(pub, b, sig) || s.Schema != "c2b-signed-bootstrap.v1" || Strict(b, &i) != nil || !i.Valid() {
		return i, deny
	}
	canonical, _ := json.Marshal(i)
	if !bytes.Equal(canonical, b) {
		return i, deny
	}
	return i, nil
}
