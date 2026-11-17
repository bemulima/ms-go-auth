# MCP-00C3B: post-consumption access-token intent (DORMANT)

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).
Dependent on Auth MCP-00C1/C2 and [MCP-00C3A discovery preview](mcp00-external-as-metadata-source.md).

Status: **SOURCE-ONLY; NO TOKEN OR HTTP ROUTE**. The real grant readback adapter,
JWT signer, JWK publication, `/token` endpoint, bearer verifier, consent UI,
client registration and Gateway `/mcp` routing are **NOT IMPLEMENTED** by this
slice. Existing frontend/IDE OAuth and CAT/Practice behavior do not change.

## Narrow Auth-owned contract

`MCPExternalTokenExchangeUsecase.Prepare` has one entrypoint that:

1. Rejects unsupported grants, client-supplied scope overrides, missing
   dependencies, non-canonical HTTPS issuer/resource, empty/duplicate policy
   scopes or an excessive access TTL. Its candidate TTL cap is five minutes,
   **not** a frozen public token lifetime.
2. Calls the existing one-use `MCPExternalCodeUsecase.Redeem`, which checks
   exact client, redirect, resource, S256 proof and performs an atomic
   PostgreSQL code consumption. No `Prepare` variant accepts arbitrary raw
   consumed-code structs or a client-provided Student identity.
3. After consumption, requires a **fresh, trusted**
   `domain.MCPExternalTokenGrantReadback` result. It must confirm the same
   persisted Student, approved client, consent, resource and current activity;
   RBAC must independently and authoritatively verify current Student status.
   Every scope needs exact current approval from client, consent, RBAC and
   the configured platform scope allowlist. A role or scope reduction fails
   closed without silently increasing or substituting scopes.
4. Returns an internal JSON-serializable **claim intent**, not a JWT:
   `iss`, `sub`, `aud`, `client_id`, `grant_id`, `scope`, `iat`, `exp`, `jti`.
   `jti` is 32 bytes of CSPRNG entropy; expiry is bounded by both policy TTL
   and the current consent expiry, without rounding into a zero-length JWT.
   Raw authorization code, PKCE verifier and code digest are never copied.

The future signed JWT profile must set `typ: at+jwt` in the **JOSE header**
(not the claims body), use approved signing keys and strictly verify token type,
signature, issuer and MCP-only resource audience. This follows [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)
and the OAuth resource-indicator model of [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html).
An ordinary Codechuman frontend JWT is never accepted as this token.

## Security boundaries and required follow-up

- The `MCPExternalTokenGrantReadback` port is **intentionally unimplemented**.
  Its future adapter must query current Auth-owned consent/client/account
  persistence and obtain a verified **signed RBAC** Student authorization
  decision. A boolean from a request, prompt, code receipt or stale cache is
  not an acceptable implementation. An outage denies exchange.
- A code is **burned** before the fresh readback. Failure or later revocation
  means the client must reauthorize; replay of the consumed code stays denied.
- Consent/RBAC may change again *after* Prepare; therefore this is not an
  atomic sign-and-revoke solution. Before activation, implement token issuance,
  persistent grant revocation and a resource-server check on **every MCP
  request** against current authority, including immutable owner ACL. No
  token should be accepted based only on a previously good readback.
- At the future HTTP boundary, require a POST with a single UTF-8 form value
  per OAuth field (RFC 6749), size caps, strict content type, safe OAuth error
  mapping, bounded rate, no tokens/authorization code/verifier in query logs.
  `Prepare` is not an HTTP parser and does not claim to enforce these guards.
- The owner must still freeze Auth issuer, MCP resource URI, client registration
  mechanism (Client ID Metadata Documents versus reviewed pre-registration),
  scopes, token TTL and delegation proof before any live adapter/route.

## Test coverage (source only)

- Targeted RED before implementation, then GREEN with an in-memory fake code
  store and fake readback; actual PostgreSQL concurrency was tested separately
  in MCP-00C2B and is **not rerun** by these unit fixtures.
- Positive bound claim intent/JSON field audit, no code/verifier in payload,
  one-time replay denial, 32-way concurrent exchange produces at most one
  intent, consent-bounded expiry.
- Negative preflight does not consume a valid code; negative fresh readback
  after consumption burns it. Deny Student deletion, client disable, consent
  revoke/expiry, RBAC denial or scope reduction, client/consent scope reduction,
  mismatched Student/client/consent/audience and backing service outage.

No HTTP, signed JWT, live RBAC or end-to-end OAuth behavior is claimed by
passing these source tests. The future owner integration must prove these
invariants with real Auth/RBAC/Gateway against disposable infrastructure.
