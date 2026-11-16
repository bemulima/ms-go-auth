package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	nats "github.com/nats-io/nats.go"
)

type mentorRuntimeNATSConnection interface {
	RequestWithContext(context.Context, string, []byte) (*nats.Msg, error)
	AuthRequired() bool
	IsConnected() bool
	Close()
}

type mentorRuntimeBroker struct {
	connection  mentorRuntimeNATSConnection
	done        chan struct{}
	once        sync.Once
	closeOnce   sync.Once
	tlsVerified atomic.Bool
}

func connectMentorRuntimeBroker(ctx context.Context, prepared *mentorRuntimePrepared, dial func(nats.Options) (mentorRuntimeNATSConnection, error)) (*mentorRuntimeBroker, error) {
	if ctx == nil || ctx.Err() != nil || prepared == nil || dial == nil {
		return nil, ErrMentorRuntimeUnavailable
	}
	brokerURL, err := url.Parse(prepared.natsOptions.Url)
	if err != nil || brokerURL == nil || brokerURL.Host == "" {
		return nil, ErrMentorRuntimeUnavailable
	}
	b := &mentorRuntimeBroker{done: make(chan struct{})}
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	options := prepared.natsOptions
	if deadline, ok := operation.Deadline(); ok && time.Until(deadline) < options.Timeout {
		options.Timeout = time.Until(deadline)
	}
	if options.Timeout <= 0 {
		return nil, ErrMentorRuntimeUnavailable
	}
	if options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.MinVersion < tls.VersionTLS12 {
		return nil, ErrMentorRuntimeUnavailable
	}
	options.TLSConfig = options.TLSConfig.Clone()
	if options.TLSConfig.RootCAs != nil {
		options.TLSConfig.RootCAs = options.TLSConfig.RootCAs.Clone()
	}
	options.TLSConfig.VerifyConnection = func(state tls.ConnectionState) error {
		// Go invokes this after normal certificate/hostname verification, before
		// HandshakeComplete is set. Successful native Connect completes the proof.
		// Never poll nats.Conn.TLSConnectionState: its status read races remote close.
		if state.Version < tls.VersionTLS12 || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			return ErrMentorRuntimeUnavailable
		}
		b.tlsVerified.Store(true)
		return nil
	}
	dialer := &mentorRuntimeFixedDialer{ctx: operation, address: brokerURL.Host}
	options.CustomDialer = dialer
	options.ClosedCB = func(*nats.Conn) { b.signal() }
	options.AsyncErrorCB = func(conn *nats.Conn, _ *nats.Subscription, _ error) {
		b.signal()
		if conn != nil {
			conn.Close()
		}
	}
	options.DisconnectedErrCB = func(conn *nats.Conn, _ error) {
		b.signal()
		if conn != nil {
			conn.Close()
		}
	}
	connection, err := dial(options)
	detached := dialer.detach()
	if err != nil || !detached || operation.Err() != nil || !b.tlsVerified.Load() || mentorCompositionMissing(connection) {
		if !mentorCompositionMissing(connection) {
			connection.Close()
		}
		return nil, ErrMentorRuntimeUnavailable
	}
	b.connection = connection
	if !b.authenticated() || operation.Err() != nil {
		b.Close()
		return nil, ErrMentorRuntimeUnavailable
	}
	return b, nil
}

func (b *mentorRuntimeBroker) RequestWithContext(ctx context.Context, subject string, body []byte) (*nats.Msg, error) {
	if ctx == nil || ctx.Err() != nil || !b.authenticated() || len(body) == 0 || len(body) > 16384 || (subject != natsadapter.MentorCanonicalAdminLookupSubject && subject != natsadapter.MentorCommittedIntentLookupSubject) {
		return nil, ErrMentorRuntimeUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	response, err := b.connection.RequestWithContext(ctx, subject, body)
	if err != nil || ctx.Err() != nil || !b.authenticated() || response == nil || len(response.Data) > 16384 {
		return nil, ErrMentorRuntimeUnavailable
	}
	return response, nil
}

func (b *mentorRuntimeBroker) Close() {
	if b != nil {
		b.signal()
		b.closeOnce.Do(func() {
			if !mentorCompositionMissing(b.connection) {
				b.connection.Close()
			}
		})
	}
}

func (b *mentorRuntimeBroker) signal() {
	if b != nil && b.done != nil {
		b.once.Do(func() { close(b.done) })
	}
}

func (b *mentorRuntimeBroker) authenticated() bool {
	if b == nil || b.done == nil || !b.tlsVerified.Load() || mentorCompositionMissing(b.connection) {
		return false
	}
	select {
	case <-b.done:
		return false
	default:
	}
	if !b.connection.IsConnected() || !b.connection.AuthRequired() {
		return false
	}
	return true
}

// NATS may learn cluster URLs from INFO. Even its initial connection must never
// fall back to a different endpoint; this dialer rejects it before any socket.
type mentorRuntimeFixedDialer struct {
	ctx     context.Context
	address string
	used    atomic.Bool
	stop    func() bool
}

func (d *mentorRuntimeFixedDialer) Dial(network, address string) (net.Conn, error) {
	if d == nil || network != "tcp" || address != d.address || d.ctx == nil || d.ctx.Err() != nil || !d.used.CompareAndSwap(false, true) {
		return nil, ErrMentorRuntimeUnavailable
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(d.ctx, network, address)
	if err != nil {
		return nil, ErrMentorRuntimeUnavailable
	}
	d.stop = context.AfterFunc(d.ctx, func() { _ = connection.Close() })
	return connection, nil
}

func (d *mentorRuntimeFixedDialer) detach() bool { return d != nil && d.stop != nil && d.stop() }

func dialMentorRuntimeBroker(options nats.Options) (mentorRuntimeNATSConnection, error) {
	return options.Connect()
}
