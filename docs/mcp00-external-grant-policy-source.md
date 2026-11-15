# MCP-00C1: Auth external Student OAuth policy source (not active)

Parent [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53). Depends on Auth [MCP-00A proposal PR #15](https://github.com/bemulima/ms-go-auth/pull/15) and the isolated [MCP-00B adapter PR #1](https://github.com/bemulima/ms-go-mcp/pull/1).

**Status:** pure `internal/usecase` validation policy and targeted tests only. **No external grant, token, HTTP handler, migration, consent UI, client registry, NATS message, or runtime access is implemented.** This document does not freeze production hosts or client registration strategy.

## Purpose and ownership

Auth currently accepts Google/GitHub provider OAuth for Codechuman login and issues web/IDE session JWTs. The new **external MCP authorization-server** flow is different. Neither the existing provider PKCE transaction nor website refresh session is reused. Auth owns the external client/consent/code/token lifecycle; the MCP adapter owns protocol and tools; domain owners retain Student object authorization.

`ValidateMCPExternalAuthorization` checks the final authorization-code issuance request after the caller has obtained, using trusted Auth-only paths:

1. The verified current Student subject and live RBAC eligibility (not passed in client JSON).
2. The verified client metadata/registry record and exact registered redirect URI.
3. The persisted explicit consent for exactly this Student, client and MCP resource audience; unexpired and not revoked.
4. The platform-approved Student scope allowlist, intersected with the client's own scopes and explicitly consented scopes. **No default scopes**. Unknown, duplicate or unconsented scopes fail the entire request.
5. `response_type=code`, `code_challenge_method=S256`, a canonical S256 challenge and exact HTTPS MCP resource URI with `/mcp` path. No wildcard resource audience or `plain` downgrade.

`VerifyMCPExternalPKCES256` separately checks the one-time token-exchange verifier (43–128 ASCII unreserved chars) against the stored 43-character base64url SHA-256 challenge using constant-time compare. It **must be called only after atomic consumption** of a short-lived code bound to the same subject/client/redirect/resource/scopes. The code store and token issuer are future changes.

OAuth client redirects are exact registered strings, with HTTPS or an explicitly registered HTTP `127.0.0.1`/`[::1]` callback. A change in loopback port currently fails. The OAuth native-client loopback port exception must be reviewed with actual MCP clients before freezing production compatibility. The function does **not** implement Client ID Metadata Document validation; that is a separate Auth-owned capability with SSRF/redirect safeguards.

## Acceptance matrix (source tests present, not executed)

- RFC 7636 S256 positive vector, mismatched/short/oversized/Unicode/space verifier, invalid/padded challenge.
- Valid consent with two explicit read scopes and exact localhost-IP registration.
- Rejection: anonymous or foreign Student, wrong client/redirect/resource audience, HTTP remote/unregistered loopback redirect, bad PKCE method or challenge.
- Rejection: blank/duplicate/wildcard/newline scopes, scope outside client or platform policy, scope missing from consent, expired/revoked/foreign grant.
- Uniform error without leaked secrets/identifiers; no URL, database or Auth session side effects.

**NOT_RUN:** Go 1.24.4 tooling, unit tests, gofmt/vet/build, agent policy, integrated OAuth and real client connection. Current executor has no Go compiler. The source is staged only for controlled review and later real test execution, not as a GREEN deliverable.

## Next Auth-owned slices

1. Approve canonical MCP issuer/resource, client metadata documents vs reviewed preregistration, consent UI semantics, source scopes, token type, and owner delegation proof. Do not create or install credential material in source.
2. Persist client/consent and hashed one-time authorization code with atomic consume, short TTL and replay denial; add reversible migration and strict negative SQL tests in an isolated database.
3. Implement browser-mediated authorization + token endpoints with verified Student session and CSRF, scope consent, PKCE code exchange, audience-bound access, refresh rotation/revocation, discovery metadata and safe errors.
4. Add a purpose-bound verifier for the MCP adapter with live role/grant checks. Do not expand existing `JWTSigner.Parse` to accept MCP audience or forward external bearer to Student/Course/Practice.
5. Connect exactly one Student read tool with owner-bound ACL; only then progress to MCP-01 and a real compatible client test. CAT/IDE Draft work remains independent until explicitly accepted.

Primary normative references: [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html), [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
