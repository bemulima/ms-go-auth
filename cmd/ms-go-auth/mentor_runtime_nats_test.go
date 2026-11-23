package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	nats "github.com/nats-io/nats.go"
)

type mentorRuntimeNATSFixture struct {
	state           tls.ConnectionState
	auth, connected bool
	err             error
	closed          atomic.Int32
	requests        int
	deadline        time.Duration
}

func (f *mentorRuntimeNATSFixture) AuthRequired() bool { return f.auth }
func (f *mentorRuntimeNATSFixture) TLSConnectionState() (tls.ConnectionState, error) {
	panic("race-unsafe native TLS state polling must not be used")
}

func mentorRuntimeGoodNATSFixture() *mentorRuntimeNATSFixture {
	certificate := &x509.Certificate{}
	return &mentorRuntimeNATSFixture{auth: true, connected: true, state: tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}}
}

// An injected successful native dial explicitly supplies the point at which
// crypto/tls would normally have verified certificates. This is not live TLS.
func mentorRuntimeFixtureDial(f *mentorRuntimeNATSFixture, capture *nats.Options) func(nats.Options) (mentorRuntimeNATSConnection, error) {
	return func(options nats.Options) (mentorRuntimeNATSConnection, error) {
		if capture != nil {
			*capture = options
		}
		dialer, ok := options.CustomDialer.(*mentorRuntimeFixedDialer)
		if !ok || options.TLSConfig == nil || options.TLSConfig.VerifyConnection == nil {
			return f, ErrMentorRuntimeUnavailable
		}
		dialer.used.Store(true)
		dialer.stop = context.AfterFunc(dialer.ctx, f.Close)
		if f.err != nil {
			return f, f.err
		}
		if err := options.TLSConfig.VerifyConnection(f.state); err != nil {
			return f, err
		}
		return f, nil
	}
}
func (f *mentorRuntimeNATSFixture) IsConnected() bool { return f.connected }
func (f *mentorRuntimeNATSFixture) Close()            { f.closed.Add(1) }
func (f *mentorRuntimeNATSFixture) RequestWithContext(ctx context.Context, subject string, body []byte) (*nats.Msg, error) {
	f.requests++
	d, _ := ctx.Deadline()
	f.deadline = time.Until(d)
	return &nats.Msg{Data: []byte("synthetic owner reply")}, f.err
}

func TestMentorRuntimeBrokerRequiresActualTLSAndAuthentication(t *testing.T) {
	cfg, loaders, _, _, _, _ := mentorRuntimeFixture(t)
	prepared, err := prepareMentorRuntime(cfg, loaders)
	if err != nil {
		t.Fatal("broker preflight unavailable")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*mentorRuntimeNATSFixture)
	}{
		{"anonymous", func(f *mentorRuntimeNATSFixture) { f.auth = false }},
		{"not connected", func(f *mentorRuntimeNATSFixture) { f.connected = false }},
		{"no TLS", func(f *mentorRuntimeNATSFixture) { f.err = errors.New("sensitive TLS diagnostic") }},
		{"unverified chain", func(f *mentorRuntimeNATSFixture) { f.state.VerifiedChains = nil }},
		{"missing peer", func(f *mentorRuntimeNATSFixture) { f.state.PeerCertificates = nil }},
		{"obsolete TLS", func(f *mentorRuntimeNATSFixture) { f.state.Version = tls.VersionTLS11 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := mentorRuntimeGoodNATSFixture()
			tc.mutate(f)
			b, err := connectMentorRuntimeBroker(context.Background(), prepared, mentorRuntimeFixtureDial(f, nil))
			if b != nil || err != ErrMentorRuntimeUnavailable || f.closed.Load() != 1 {
				t.Fatal("untrusted broker admitted or not closed")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if b, err := connectMentorRuntimeBroker(ctx, prepared, func(nats.Options) (mentorRuntimeNATSConnection, error) { calls++; return nil, nil }); b != nil || err != ErrMentorRuntimeUnavailable || calls != 0 {
		t.Fatal("cancelled startup attempted dial")
	}
}

func TestMentorRuntimeBrokerFixedSubjectsAndFailureLifecycle(t *testing.T) {
	cfg, loaders, _, _, _, _ := mentorRuntimeFixture(t)
	prepared, err := prepareMentorRuntime(cfg, loaders)
	if err != nil {
		t.Fatal("broker preflight unavailable")
	}
	f := mentorRuntimeGoodNATSFixture()
	var options nats.Options
	b, err := connectMentorRuntimeBroker(context.Background(), prepared, mentorRuntimeFixtureDial(f, &options))
	if err != nil || b == nil || options.CustomDialer == nil || options.ClosedCB == nil || options.AsyncErrorCB == nil {
		t.Fatal("dedicated runtime hooks missing")
	}
	defer b.Close()
	for _, subject := range []string{natsadapter.MentorCanonicalAdminLookupSubject, natsadapter.MentorCommittedIntentLookupSubject} {
		if msg, err := b.RequestWithContext(context.Background(), subject, []byte("{}")); err != nil || msg == nil || f.deadline <= 0 || f.deadline > 3*time.Second {
			t.Fatal("bounded real requester not used")
		}
	}
	if _, err := b.RequestWithContext(context.Background(), "rbac.assign-role", []byte("{}")); err != ErrMentorRuntimeUnavailable || f.requests != 2 {
		t.Fatal("foreign subject forwarded")
	}
	if _, err := options.CustomDialer.Dial("tcp", "foreign.example:4222"); err != ErrMentorRuntimeUnavailable {
		t.Fatal("fallback address not blocked before socket")
	}
	if _, err := options.CustomDialer.Dial("tcp", "broker.example:4222"); err != ErrMentorRuntimeUnavailable {
		t.Fatal("second connection attempt not blocked before socket")
	}
	options.ClosedCB(nil)
	select {
	case <-b.done:
	default:
		t.Fatal("closed broker did not stop runtime")
	}
	if _, err := b.RequestWithContext(context.Background(), natsadapter.MentorCanonicalAdminLookupSubject, []byte("{}")); err != ErrMentorRuntimeUnavailable || f.requests != 2 {
		t.Fatal("closed broker reused")
	}
}

func TestMentorRuntimeBrokerRejectsMissingNormalTLSVerification(t *testing.T) {
	cfg, loaders, _, _, _, _ := mentorRuntimeFixture(t)
	prepared, err := prepareMentorRuntime(cfg, loaders)
	if err != nil {
		t.Fatal("broker preflight unavailable")
	}
	f := &mentorRuntimeNATSFixture{auth: true, connected: true, state: tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true, VerifiedChains: [][]*x509.Certificate{{{}}}}}
	b, err := connectMentorRuntimeBroker(context.Background(), prepared, func(nats.Options) (mentorRuntimeNATSConnection, error) { return f, nil })
	if b != nil || err != ErrMentorRuntimeUnavailable || f.closed.Load() != 1 {
		t.Fatal("broker accepted without normal TLS verification callback provenance")
	}
}
