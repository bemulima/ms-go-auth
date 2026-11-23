# Mentor executable runtime wiring

MENT-01A default-off source wiring, not live runtime acceptance. No operator
configuration, credentials, broker, database or deployed listener is changed by
this implementation. The three existing
[HTTP authority operations](../.ai/contracts/mentor-http-authority-v1.md), role
proofs and signed owner lookup subjects are unchanged.

## Explicit configuration

| Setting | Meaning |
| --- | --- |
| `AUTH_MENTOR_ENABLED` | Defaults to `false`; the only activation switch |
| `AUTH_MENTOR_HTTPS_ADDR` | Explicit bind host and nonzero port; different from the existing HTTP port |
| `AUTH_MENTOR_TLS_CERT_FILE` | Absolute bounded regular TLS certificate-chain file |
| `AUTH_MENTOR_TLS_KEY_FILE` | Absolute bounded regular owner-only TLS private-key file |
| `AUTH_MENTOR_ROLE_DECISION_PRIVATE_KEY`, `AUTH_MENTOR_ROLE_DECISION_PUBLIC_KEY` | Matched dedicated RSA role-proof PEM pair |
| `AUTH_MENTOR_OWNER_LOOKUP_PRIVATE_KEY`, `AUTH_MENTOR_OWNER_LOOKUP_PUBLIC_KEY` | Matched distinct RSA lookup-proof PEM pair |
| `AUTH_MENTOR_RBAC_REPLY_PUBLIC_KEY` | Pinned canonical Admin reply RSA key |
| `AUTH_MENTOR_INTENT_REPLY_PUBLIC_KEY` | Independently pinned committed Mentor intent reply RSA key |
| `AUTH_MENTOR_NATS_URL` | Exactly one `tls://host:port`, no credentials, path, query, fragment or fallback list |
| `AUTH_MENTOR_NATS_CREDENTIALS_FILE` | Absolute bounded regular owner-only NATS user credentials file |
| `AUTH_MENTOR_NATS_CA_FILE` | Optional absolute bounded regular trust-root file; otherwise system roots |
| `AUTH_DB_MIGRATE_ON_START` | Must be `false` for enabled Mentor startup; owner migration is a separate action |

The disabled branch does not inspect Mentor keys or files, create an additional
connection/server, or alter legacy startup migrations and HTTP behavior. The
existing migration default remains unchanged when Mentor is disabled.

Enabled preflight runs before DB open, schema operations or any network
connection. It validates endpoints and required key material, TLS server usage,
SAN, current certificate validity, matched key pair, and purpose separation.
The four Mentor RSA domains remain distinct from each other and from configured
access/reviewer RSA material. TLS key material must differ from these and any
configured signup Ed25519 key. No fallback to access, signup or reviewer signing
keys is selected. Existing access-parser configuration is used as-is; the new
runtime neither changes the access JWT algorithm nor adds an alternate parser.

Files are read through bounded snapshots (maximum 32 KiB each), with no-follow,
nonblocking regular-file checks before and after open. Private-key and NATS
credentials must belong to the runtime UID and exclude group/other access.
Symlinks, special files, replacement races and oversized files fail closed. File errors,
paths, proofs, credentials and raw driver/broker diagnostics are not logged.
Native `nats.UserCredentialBytes` callbacks operate on the credential snapshot,
not later file rereads. Preflight verifies the JWT subject's user NKey against a
fixed signed challenge. This proves local subject/seed consistency only: the
actual authenticated broker still owns issuer, expiry and ACL validation.

## Concrete wiring and lifecycle

`New` uses Auth's existing real database and configured access-token signer with
`NewMentorComposition`, but supplies a **separate** Mentor owner requester.
The global legacy NATS connection remains unchanged and is never substituted.
The dedicated connection requires TLS 1.2+, certificate/hostname verification,
an authenticated user credential and the actual broker's `AuthRequired` flag.
Normal Go certificate/hostname verification must invoke the private
`VerifyConnection` callback with peer certificates and a verified chain, and
native `Connect` must then succeed. This avoids polling the pinned NATS
library's race-unsafe `TLSConnectionState` method during remote disconnects.
No anonymous, plaintext, insecure verification, reconnect or automatic retry is
allowed. A fixed-endpoint dialer rejects INFO-discovered/fallback destinations
before opening a socket and permits only one dial attempt. A cancellation guard
retains ownership of the raw socket until native `Connect` finishes;
connect/handshake is bounded to five seconds (or an earlier caller deadline),
and each owner request retains the three-second bound.
Only the two frozen owner lookup subjects may be requested.

The existing Echo listener stays plaintext and never receives these routes.
Enabled `Run` starts a separate `http.Server.ListenAndServeTLS` using the already
loaded certificate, no late key-file read, and HTTP/1.1 with TLS 1.2 or later.
Header/read/write/idle deadlines are 3/5/10/30 seconds, maximum headers 16 KiB.
HTTP/2 is disabled for this narrow listener so the reviewed timeout behavior is
not silently replaced by another protocol. HTTP error logging is silent; wire
errors still use the existing sanitized JSON contract.

Cancellation, either listener stopping unexpectedly, or dedicated broker
disconnect/asynchronous error stops both listeners. Request contexts are
cancelled, HTTP shutdown is bounded to five seconds with forced-close fallback,
and dedicated NATS ownership is closed before legacy dependencies are released.
No stored Admin/session identity or previous proof can renew authority. With
Mentor disabled, the existing `Run` path and dependency lifetimes are unchanged.

## Verification limits

`mentor-runtime-targeted`, `mentor-runtime-race`, `mentor-runtime-vet` and
`mentor-runtime-build` are narrow no-socket checks. Tests use explicit isolated
configuration maps, ephemeral in-memory keys, synthetic private temporary files,
native credential callbacks, injected connection/server lifecycles and HTTP
recorders. They do not call `New`, real NATS `Connect`, `ListenAndServeTLS`,
`httptest.NewServer`, Docker, SQL migrations or a real database. A static call-site
test separately guards the actual executable wiring and early preflight order.

Mounted HTTPS acceptance, listener failure/slow-client tests on real sockets,
actual authenticated broker ACLs and signed owners, PostgreSQL session behavior,
deployment, key custody and executable Gherkin remain unverified runtime gates.
The source change is not a claim that MENT-01A is completely accepted.
