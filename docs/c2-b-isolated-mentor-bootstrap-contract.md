# C2-B isolated reviewer bootstrap

Status: OWNER_AGREED_IMPLEMENTATION_ONLY; INDEPENDENT_REVIEW_PENDING. Explicit agreement received in task chat. Implementation and independent review gates remain separate.

Purpose: finish retained Runtime instance `8ada3ddb-c548-4991-9d44-51677c5ebff3`, FINAL `b332012c-daaa-49fe-bb37-07cd16e3e4ab`. No new TaskInstance/Submit, changed revision or production authorization policy.

## Fixed authority and isolation

Only closed, separately invoked owner verification CLI commands, absent from production HTTP routes and server startup. Require explicit fixture enablement, test/proof environment, exact ownership marker for project `c2b-proof-20261016`, exact allowlisted loopback isolated Auth/RBAC databases, dedicated fixture DB principals and restricted marker/key files. Reject production/missing/mismatched environment before network/database effects. Runtime DB credentials have no bootstrap grant authority. The ownership marker pins run, databases, public signing key fingerprint and exact retained execution identity.

Server-owned mapping has only two entries: reviewer `01a58012-c6df-58a4-b1ac-0f646d7f47c5` → role `mentor`, and negative-test learner `fab713c1-218e-49cb-8e57-7bc9bf8606a8` → role `student`. Both use deterministic run-scoped `.invalid` emails. No caller-selected role/email/scope; no ADMIN; no role argument in registration or public API. The learner entry is solely for the required authenticated STUDENT-denied check and cannot select the reviewer binding. Passwords enter bounded stdin only. No JWT is produced by bootstrap.

## Owner sequence and provenance

1. Auth verification CLI prepares a deterministic immutable intent covering run/operation/principal/email/fixed-role/scope/execution identity. A dedicated fixture Ed25519 key signs the exact bounded intent. This key is separate from JWT and production signup authority. Preparing creates no credential/session.
2. RBAC verification CLI validates environment/marker, dedicated public key/signature, strict schema, fixed mapping and exact run/operation. In one owner repository transaction, ensure only the isolated `mentor` role definition (not global canonical production reference data), create the exact default global/core assignment and immutable bootstrap receipt. Existing incompatible principal role/identity or changed replay conflicts; no role update/upgrading an existing student. Student probe uses existing canonical student definition. This CLI is the explicitly approved provisioning boundary; no operator SQL role writes. HTTP mutation admission and signed production student-signup RPC remain unchanged.
3. Auth finalization validates the exact RBAC receipt, independently confirms its fixed role through the existing authenticated broker `rbac.checkRole`, then creates the exact Auth credential/identity plus immutable audit receipt in one transaction. It never resets an existing password, adopts a conflicting identity or issues a token while provisioning is incomplete. The isolated test identity may carry the email-verified flag required by normal signin, explicitly recorded as owner-authorized test bootstrap rather than real email verification. Lost response/restart replays the same operation; interrupted RBAC-before-Auth work remains auditable and recoverable.
4. Real Auth signin creates an ordinary persisted refresh session and signed access token. For this audited isolated reviewer only, Auth resolves verified RBAC `mentor` membership and emits the exact `MENTOR` claim required by existing Runtime review. Enable this lookup/claim only under the validated C2-B runtime environment and matching Auth bootstrap receipt; production startup with fixture enablement must reject. Other role claims and public signup behavior stay unchanged. Gateway validates the issued token through existing Auth, overwrites supplied actor headers, and forwards the authoritative role; no Gateway bypass or fabricated token.

## Contracts and storage

New interfaces: verification-only Auth prepare/finalize CLI and RBAC apply CLI, strict versioned signed intent and immutable owner receipts. No new public/internal HTTP mutation endpoint, broker mutation subject or production grant matrix. Existing `rbac.checkRole`, signin/verify and Gateway Practice V2 review route are reused. Add minimal immutable audit/intent tables through owner migrations only to new isolated Auth/RBAC DBs; no backfill or modification of current C2-B Runtime/Student DBs. Rollback refuses retained receipts. Preserve legacy student fixture and production signup contract.

## Proof and gates

Deny production/wrong marker/key/DB/run/principal/role, extra fields, incompatible replay, existing conflicting roles and password reset attempts. Test atomic receipts, repeat/restart and independent role readback. Real proof: issue learner and MENTOR tokens via signin; Gateway denies absent/invalid token and forged role headers; real learner gets review 403; MENTOR approves exact retained FINAL; replay/conflict/completion/lock, committed outbox→JetStream→Student receipt/frozen requirements/mastery/progression are checked without new submissions. Keep tokens/keys/private material in restricted files; public evidence contains only provenance IDs/digests/outcomes. No C2-C or LLM calls.

Publication requires independent Auth/RBAC review plus separate five-owner C2-B review. Implementing agent cannot issue independent APPROVE. If a new execution blocker requires another owner contract, retain completed stages and identify that exact boundary.

Implementation entrypoints: Auth `go run ./cmd/ms-go-auth-c2b-fixture prepare mentor|learner` and `finalize mentor|learner <private-rbac-receipt-file>` (password on stdin); RBAC `go run ./cmd/ms-rbac-c2b-fixture apply` (signed intent on stdin). Enablement: `C2B_FIXTURE_ENABLED=true`, `C2B_ENV=c2b-proof`, owner APP_ENV=c2b-proof, `C2B_OWNERSHIP_MARKER`, exact `C2B_FIXTURE_DSN`, and Auth-only `C2B_AUTH_SIGNING_KEY`. Marker expires within 24h, fixes key/run/DB/execution; files must be private regular files. New migration Auth0006 / RBAC004 stores immutable receipts, rejects update/delete/truncate and nonempty rollback. Auth runtime additionally requires `AUTH_C2B_PROOF_ENABLED=true`, loopback `c2b_auth_runtime`/exact DB, migrations disabled and valid marker; audited mentor role lookup rejects expired authority on token issuance. No fixture key in Auth runtime, no JWT key in bootstrap. Runtime credentials cannot insert bootstrap audit or assign roles.

Least-privilege live characterization: SELECT FOR KEY SHARE on role required UPDATE privilege; the new bootstrap's unnecessary row lock was removed, keeping its fixture principal INSERT/SELECT-only. FK plus assignment/audit transaction preserves binding. No broader database grants were introduced to make the proof pass.

## R1 effective PostgreSQL configuration gate

The retained isolated destination is exactly `127.0.0.1:49920`; database and
principal remain the fixed owner allowlist above. Require a literal `postgres`
URL with an explicit nonempty password and exactly `sslmode=disable` as the
query. Reject extra/duplicate/encoded query parameters, encoded identity/path,
other hosts/ports, multi-host fallback, service files and any present `PG*`
environment variable (including an empty one). Password escaping is supported;
passwords and driver parse errors are never included in gate errors.

`PrepareConnection` validates the marker/environment and parses with the actual
pgx driver before any database opener runs. It checks effective host, port,
user, database, TLS, runtime options and fallback destinations. The CLI uses
that parsed configuration object: Auth passes pgx stdlib's SQL pool to GORM
through `postgres.Config.Conn`; RBAC passes the validated pool configuration
to `pgxpool.NewWithConfig`. Neither CLI reconnects using the raw DSN. Auth proof runtime likewise passes
the validated runtime-principal configuration to pgx stdlib/GORM; production
connection setup is unchanged.

Regressions cover the original host override, endpoint/identity/options/service
overrides, duplicates/encoding, PG environment, wrong destination and production.
CLI opener spies prove zero connection attempts on denial. An in-memory
PostgreSQL protocol fixture exercises the real positive GORM/pgxpool connection
and checks the fixed startup user/database without touching preserved stores.
This remediation still requires separate independent review before publication.
