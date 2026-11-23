package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/example/auth-service/config"
	"github.com/golang-jwt/jwt/v5"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

var ErrMentorRuntimeUnavailable = errors.New("mentor runtime unavailable")

type mentorRuntimeLoaders struct {
	tlsPair  func(string, string) (tls.Certificate, error)
	readFile func(string, bool) ([]byte, error)
	now      func() time.Time
}

type mentorRuntimePrepared struct {
	composition MentorCompositionConfig
	address     string
	certificate tls.Certificate
	natsOptions nats.Options
}

func prepareMentorRuntime(cfg *config.Config, loaders mentorRuntimeLoaders) (*mentorRuntimePrepared, error) {
	if cfg != nil && !cfg.MentorEnabled {
		return nil, nil
	}
	if cfg == nil || cfg.DBMigrateOnStart || loaders.tlsPair == nil || loaders.readFile == nil || loaders.now == nil {
		return nil, ErrMentorRuntimeUnavailable
	}
	host, port, err := net.SplitHostPort(cfg.MentorHTTPSAddress)
	if err != nil || !mentorRuntimeHost(host) || !mentorRuntimePort(port) || port == cfg.HTTPPort ||
		!mentorRuntimePath(cfg.MentorTLSCertFile) || !mentorRuntimePath(cfg.MentorTLSKeyFile) || !mentorRuntimePath(cfg.MentorNATSCredentialsFile) {
		return nil, ErrMentorRuntimeUnavailable
	}
	broker, err := url.Parse(cfg.MentorNATSURL)
	if err != nil || broker == nil || broker.Scheme != "tls" || broker.User != nil || broker.Opaque != "" || broker.Path != "" || broker.RawPath != "" || broker.RawQuery != "" || broker.ForceQuery || broker.Fragment != "" || broker.RawFragment != "" || !mentorRuntimeHost(broker.Hostname()) || !mentorRuntimePort(broker.Port()) || broker.Host != net.JoinHostPort(broker.Hostname(), broker.Port()) {
		return nil, ErrMentorRuntimeUnavailable
	}
	composition := MentorCompositionConfig{Enabled: true, RoleDecision: MentorCompositionKeyPair{PrivatePEM: cfg.MentorRolePrivateKey, PublicPEM: cfg.MentorRolePublicKey}, OwnerLookup: MentorCompositionKeyPair{PrivatePEM: cfg.MentorLookupPrivateKey, PublicPEM: cfg.MentorLookupPublicKey}, RBACReplyPublicPEM: cfg.MentorRBACReplyPublicKey, MentorReplyPublicPEM: cfg.MentorIntentReplyPublicKey}
	if !mentorCompositionDistinctKeys(composition) {
		return nil, ErrMentorRuntimeUnavailable
	}
	certificate, err := loaders.tlsPair(cfg.MentorTLSCertFile, cfg.MentorTLSKeyFile)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrMentorRuntimeUnavailable
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	now := loaders.now()
	if err != nil || now.IsZero() || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA || len(leaf.DNSNames)+len(leaf.IPAddresses) == 0 {
		return nil, ErrMentorRuntimeUnavailable
	}
	serverUsage := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverUsage = true
		}
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !serverUsage || !ok || mentorCompositionMissing(signer) || !mentorRuntimeExactKey(leaf.PublicKey, signer.Public()) || !mentorRuntimeDistinctKeys(cfg, composition, leaf.PublicKey) {
		return nil, ErrMentorRuntimeUnavailable
	}
	certificate.Leaf = leaf
	options := nats.GetDefaultOptions()
	options.Url, options.Servers = cfg.MentorNATSURL, nil
	options.Name = "ms-go-auth-mentor-owner"
	options.SkipHostLookup = true
	options.Secure, options.AllowReconnect, options.RetryOnFailedConnect = true, false, false
	options.MaxReconnect, options.ReconnectBufSize = 0, -1
	options.Timeout, options.DrainTimeout, options.FlusherTimeout = 5*time.Second, 5*time.Second, 3*time.Second
	options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: broker.Hostname()}
	if cfg.MentorNATSCAFile != "" {
		if !mentorRuntimePath(cfg.MentorNATSCAFile) {
			return nil, ErrMentorRuntimeUnavailable
		}
		material, readErr := loaders.readFile(cfg.MentorNATSCAFile, false)
		pool := x509.NewCertPool()
		if readErr != nil || len(material) == 0 || len(material) > mentorRuntimeFileLimit || !pool.AppendCertsFromPEM(material) {
			return nil, ErrMentorRuntimeUnavailable
		}
		options.TLSConfig.RootCAs = pool
	}
	credential, err := loaders.readFile(cfg.MentorNATSCredentialsFile, true)
	if err != nil || len(credential) == 0 || len(credential) > mentorRuntimeFileLimit || nats.UserCredentialBytes(credential)(&options) != nil || !mentorRuntimeCredentialPair(options) {
		return nil, ErrMentorRuntimeUnavailable
	}
	return &mentorRuntimePrepared{composition: composition, address: cfg.MentorHTTPSAddress, certificate: certificate, natsOptions: options}, nil
}

func newMentorHTTPSServer(prepared *mentorRuntimePrepared, deps MentorCompositionDependencies) (*http.Server, error) {
	if prepared == nil {
		return nil, ErrMentorRuntimeUnavailable
	}
	handler, err := NewMentorComposition(prepared.composition, deps)
	if err != nil || handler == nil {
		return nil, ErrMentorRuntimeUnavailable
	}
	return &http.Server{Addr: prepared.address, Handler: handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{prepared.certificate}, NextProtos: []string{"http/1.1"}},
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384,
		ErrorLog: log.New(io.Discard, "", 0)}, nil
}

type mentorServerLifecycle struct {
	start    func() error
	shutdown func(context.Context) error
	close    func() error
}

func runMentorServers(ctx context.Context, servers []mentorServerLifecycle, brokerDone <-chan struct{}) error {
	if ctx == nil {
		return ErrMentorRuntimeUnavailable
	}
	if ctx.Err() != nil {
		return nil
	}
	if len(servers) != 2 || brokerDone == nil {
		return ErrMentorRuntimeUnavailable
	}
	select {
	case <-brokerDone:
		return ErrMentorRuntimeUnavailable
	default:
	}
	for _, server := range servers {
		if server.start == nil || server.shutdown == nil || server.close == nil {
			return ErrMentorRuntimeUnavailable
		}
	}
	results := make(chan error, len(servers))
	for _, server := range servers {
		go func(s mentorServerLifecycle) { results <- s.start() }(server)
	}
	remaining := len(servers)
	var outcome error
	select {
	case <-ctx.Done():
	case <-brokerDone:
		outcome = ErrMentorRuntimeUnavailable
	case <-results:
		remaining--
		if ctx.Err() == nil {
			outcome = ErrMentorRuntimeUnavailable
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopped := make(chan error, len(servers))
	for _, server := range servers {
		go func(s mentorServerLifecycle) {
			err := s.shutdown(shutdownCtx)
			if err != nil {
				_ = s.close()
			}
			stopped <- err
		}(server)
	}
	for range servers {
		select {
		case err := <-stopped:
			if err != nil {
				outcome = ErrMentorRuntimeUnavailable
			}
		case <-shutdownCtx.Done():
			for _, s := range servers {
				_ = s.close()
			}
			return ErrMentorRuntimeUnavailable
		}
	}
	for remaining > 0 {
		select {
		case <-results:
			remaining--
		case <-shutdownCtx.Done():
			for _, s := range servers {
				_ = s.close()
			}
			return ErrMentorRuntimeUnavailable
		}
	}
	return outcome
}

const mentorRuntimeFileLimit = 32768

func defaultMentorRuntimeLoaders() mentorRuntimeLoaders {
	return mentorRuntimeLoaders{tlsPair: func(certPath, keyPath string) (tls.Certificate, error) {
		cert, err := readMentorRuntimeFile(certPath, false)
		if err != nil {
			return tls.Certificate{}, ErrMentorRuntimeUnavailable
		}
		key, err := readMentorRuntimeFile(keyPath, true)
		if err != nil {
			return tls.Certificate{}, ErrMentorRuntimeUnavailable
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return tls.Certificate{}, ErrMentorRuntimeUnavailable
		}
		return pair, nil
	}, readFile: readMentorRuntimeFile, now: time.Now}
}

func readMentorRuntimeFile(path string, private bool) ([]byte, error) {
	if !mentorRuntimePath(path) {
		return nil, ErrMentorRuntimeUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > mentorRuntimeFileLimit || (private && !mentorRuntimePrivateFileOwner(info)) {
		return nil, ErrMentorRuntimeUnavailable
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrMentorRuntimeUnavailable
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil || !os.SameFile(info, stat) || !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > mentorRuntimeFileLimit || (private && !mentorRuntimePrivateFileOwner(stat)) {
		return nil, ErrMentorRuntimeUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, mentorRuntimeFileLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > mentorRuntimeFileLimit {
		return nil, ErrMentorRuntimeUnavailable
	}
	return raw, nil
}

func mentorRuntimePrivateFileOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}

func mentorRuntimePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}
func mentorRuntimePort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}
func mentorRuntimeHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			alphanumeric := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !alphanumeric && c != '-' {
				return false
			}
		}
	}
	return true
}

func mentorRuntimeCredentialPair(options nats.Options) bool {
	if options.UserJWT == nil || options.SignatureCB == nil {
		return false
	}
	token, err := options.UserJWT()
	if err != nil || len(token) > mentorRuntimeFileLimit {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil || !nkeys.IsValidPublicUserKey(claims.Subject) {
		return false
	}
	key, err := nkeys.FromPublicKey(claims.Subject)
	if err != nil {
		return false
	}
	defer key.Wipe()
	challenge := []byte("ms-go-auth-mentor-runtime-credential-pair-v1")
	signature, err := options.SignatureCB(challenge)
	return err == nil && key.Verify(challenge, signature) == nil
}

func mentorRuntimeSameKey(a, b crypto.PublicKey) bool {
	if x, ok := a.(*rsa.PublicKey); ok {
		if y, ok := b.(*rsa.PublicKey); ok {
			return x != nil && y != nil && x.N != nil && y.N != nil && x.N.Cmp(y.N) == 0
		}
	}
	return mentorRuntimeExactKey(a, b)
}

func mentorRuntimeExactKey(a, b crypto.PublicKey) bool {
	x, ex := x509.MarshalPKIXPublicKey(a)
	y, ey := x509.MarshalPKIXPublicKey(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}

func mentorRuntimeRSAPair(pair MentorCompositionKeyPair) (*rsa.PublicKey, bool) {
	priv, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pair.PrivatePEM))
	if err != nil || priv == nil || priv.N == nil || priv.N.BitLen() < 2048 || priv.Validate() != nil {
		return nil, false
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pair.PublicPEM))
	if err != nil || pub == nil || pub.N == nil || pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		return nil, false
	}
	return pub, true
}

func mentorRuntimeDistinctKeys(cfg *config.Config, composition MentorCompositionConfig, tlsKey crypto.PublicKey) bool {
	switch key := tlsKey.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.N.BitLen() < 2048 {
			return false
		}
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.Curve.Params().BitSize < 256 {
			return false
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return false
		}
	default:
		return false
	}
	role, ok := mentorRuntimeRSAPair(composition.RoleDecision)
	if !ok {
		return false
	}
	lookup, ok := mentorRuntimeRSAPair(composition.OwnerLookup)
	if !ok {
		return false
	}
	admin, err := jwt.ParseRSAPublicKeyFromPEM([]byte(composition.RBACReplyPublicPEM))
	if err != nil {
		return false
	}
	intent, err := jwt.ParseRSAPublicKeyFromPEM([]byte(composition.MentorReplyPublicPEM))
	if err != nil {
		return false
	}
	newKeys := []crypto.PublicKey{role, lookup, admin, intent}
	var existing []crypto.PublicKey
	if cfg.JWTPrivateKey != "" || cfg.JWTPublicKey != "" {
		access, valid := mentorRuntimeRSAPair(MentorCompositionKeyPair{PrivatePEM: cfg.JWTPrivateKey, PublicPEM: cfg.JWTPublicKey})
		if !valid {
			return false
		}
		existing = append(existing, access)
	} else if cfg.JWTSecret == "" {
		return false
	}
	if cfg.RBACPermissionDecisionPublicKey != "" {
		reviewer, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.RBACPermissionDecisionPublicKey))
		if err != nil || reviewer.N == nil || reviewer.N.BitLen() < 2048 {
			return false
		}
		existing = append(existing, reviewer)
	}
	if cfg.RBACSignupPrivateKey != "" {
		raw, err := base64.StdEncoding.Strict().DecodeString(cfg.RBACSignupPrivateKey)
		if err != nil || len(raw) != ed25519.PrivateKeySize || base64.StdEncoding.EncodeToString(raw) != cfg.RBACSignupPrivateKey {
			return false
		}
		key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(raw, key) {
			return false
		}
		existing = append(existing, key.Public())
	}
	for _, key := range newKeys {
		if mentorRuntimeSameKey(key, tlsKey) {
			return false
		}
		for _, old := range existing {
			if mentorRuntimeSameKey(key, old) {
				return false
			}
		}
	}
	for _, old := range existing {
		if mentorRuntimeSameKey(old, tlsKey) {
			return false
		}
	}
	return true
}
