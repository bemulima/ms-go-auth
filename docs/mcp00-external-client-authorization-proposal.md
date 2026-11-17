# MCP-00A: external Student MCP authorization proposal (NOT FROZEN)

Parent: [Codechuman MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).
Status: **DESIGN PROPOSAL / SOURCE ONLY**. No route, grant, schema, token, permission, migration, deployment or runtime behavior is activated by this document.

## Problem and current baseline

`ms-go-auth` currently consumes Google/GitHub OAuth identities for Codechuman sign-in. It also issues its own session-bound frontend access/refresh JWTs and verifies access-token session revocation. This does **not** make it an OAuth authorization server for third-party ChatGPT, Claude or other MCP clients. A signed Codechuman frontend token is **not** automatically an MCP access token.

The current `main` Auth HTTP router has no external client authorization-code/token/consent/discovery endpoints. Gateway's general bearer check is guest-capable; Student legacy HTTP relies on trusted Gateway actor headers; RBAC's generic permission-check API is not a ready-made Student MCP PDP. None may be treated as a completed external MCP security boundary.

Source baseline (2026-11-15):

- [Auth `710318b`](https://github.com/bemulima/ms-go-auth/blob/710318b547e625d300bc309d2ffcfb034478e4f2/internal/transport/http/api/v1/router.go) — current routes; [owned Auth contract](https://github.com/bemulima/ms-go-auth/blob/710318b547e625d300bc309d2ffcfb034478e4f2/docs/http-contract.md).
- [Gateway `c00d8ed`](https://github.com/bemulima/ms-gateway/blob/c00d8ed51d36dc453ca78d368c87bbb12002e7fe/.ai/contracts/authentication.yaml) — actor-header and bearer boundary.
- [RBAC `1a553f0`](https://github.com/bemulima/ms-go-rbac/blob/1a553f0b5a7bd06c4c44a7cca9f9f26c6932a8d8/docs/messaging-contract.md) — current role/permission contracts.
- [Student `24d0539`](https://github.com/bemulima/ms-go-student/blob/24d05391b06b56d96d507306570481d38a8ffc6b/.ai/contracts/http.yaml) — owner-bound learning APIs.

## Proposed ownership

| Owner | New responsibility | Explicitly not owned |
| --- | --- | --- |
| Auth | OAuth authorization-server discovery, registered external client identity, consent/grant, authorization code + PKCE, scoped audience-bound tokens, refresh rotation and revocation | MCP protocol, TaskInstance, learning contents, business ACL |
| MCP adapter (separate service proposed) | Protected resource metadata, Streamable HTTP, tool catalog, grant/scope admission, safe DTO projection, audit and attribution | Passwords, tokens issued on its own authority, domain writes or Mastery decisions |
| Gateway | Exact external `/mcp` route and deny-by-default transport boundary after an approved service exists | OAuth grant decisions or owner ACL |
| RBAC | Authoritative, current role checks under approved scope; existing role semantics preserved | OAuth consent, MCP scopes or task permission inferred from role alone |
| Student, Course, Practice, Planner, Sandbox and other domain owners | Their existing object-level authorization, immutable revisions and business invariants | Trust in an unverified client-supplied actor or MCP prompt |

Do not forward the external MCP bearer into legacy owner services, issue a broad internal token to a model, or trust `X-User-ID`, `X-User-Role`, cookies, `student_id` JSON or client name. A separately documented, short-lived, audience/purpose-bound delegation proof or a fresh owner-side Auth/RBAC check is required for any downstream request. No generic `rbac.checkPermission` rollout as an implicit side effect.

## Proposed OAuth / resource-server contract

This is a **candidate**, not a claim of implemented endpoints or a final URL.

1. Auth publishes authorization-server metadata (RFC 8414 or OIDC discovery), issuer, authorization and token endpoints, supported `S256` PKCE, registration methods and safe scopes. The exact public paths and issuer are to be frozen jointly with Gateway; do not infer them from `/api/v1/auth/oauth/:provider/*`.
2. MCP publishes OAuth Protected Resource Metadata (RFC 9728) for one canonical HTTPS resource URI, provisionally `https://<host>/mcp`, advertising the Auth issuer. `<host>` is a placeholder; no production domain is selected here.
3. Prefer OAuth Client ID Metadata Documents when the client supports them; allow reviewed pre-registration for compatibility. Dynamic registration is optional and must not be made anonymously permissive by default. Every external client ID/redirect URI is validated against the selected registration mechanism. No official MCP registry registration is required.
4. Browser-mediated authorization code + PKCE `S256`; verify issuer, client, response state, exact redirect URI, code verifier, `resource` and requested scopes. An authorization code is single-use, bound to one authenticated Student, client, redirect, resource and approved scope set, with a short TTL. Unconsented or unknown scopes fail closed.
5. Consent grants **no scopes by default**. A scoped read-only consent can be requested first; mutating scopes need explicit additional consent (step-up) and may be disabled for a client. The platform restricts the grant to the intersection of requested scopes, student role and platform policy. Actual object authorization remains the domain owner's responsibility.
6. Access token is bound to the canonical MCP resource audience and issuer, the Student subject, client identity, grant identity, scopes, issue/expiry and revocation state. Authentication must reject wrong audience/issuer, token type, expired or revoked grant/session, missing scope and stale role. Do not broaden the existing frontend JWT verifier's accepted audience as a shortcut.
7. Refresh tokens, if issued, are bound to the same client/grant/resource and rotated for public clients. Revoke/disconnect terminates the grant and invalidates subsequent access; document token lifetime and replay handling before implementation. Revocation may log safe status codes and correlation IDs, never credentials or token values.
8. Every MCP HTTP request carries its own bearer; no URL query token, cross-origin credential reuse or bearer forwarding to unrelated services. Return a standards-aligned `401` for absent/invalid token, `403` with scoped challenge for insufficient scope, and uniformly safe owner-denial projections. Every request is bounded and correlated without logging tokens, authorization codes, verifiers or student content.
9. Prompts/tool text and a client's declared app name are **untrusted data**. The server records verified grant/client ID and the `MCP` channel separately from user-reported application name and AI-assistance metadata. MCP origin does not prove who wrote the solution.

## Version / SDK decision gate

- The [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) requires resource metadata, OAuth discovery and resource-bound access tokens for protected HTTP servers; the current [Streamable HTTP binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) must be considered alongside backward compatibility.
- The [official Go SDK](https://github.com/modelcontextprotocol/go-sdk) `v1.8.0` supports protocol `2026-07-28` but its `go.mod` requires **Go 1.25.0**. `v1.4.0` targets Go 1.24 but does not cover the latest protocol version. Select and pin the service's Go toolchain/SDK only after client compatibility and deployment review; **do not force-upgrade Auth, Gateway or existing services** because of an MCP adapter.

## CAT / IDE coupling: precise boundary

CAT [Epic #49](https://github.com/bemulima/learning-platform-business/issues/49) is primarily a Practice business-model change, **not an Auth authorization-server change**. Its Draft [Catalog #42](https://github.com/bemulima/ms-go-pet-project-orchestrator/pull/42), [Gateway #57](https://github.com/bemulima/ms-gateway/pull/57) and [RBAC #13](https://github.com/bemulima/ms-go-rbac/pull/13) nevertheless add or consume strict existing Auth/RBAC checks for Student catalog access. They introduce no OAuth consent or MCP resource audience. Do not wait for all CAT work to implement an isolated Auth grant foundation, but do not expose draft CAT V2 / V5 operations as available MCP tools.

IDE [Epic #28](https://github.com/bemulima/learning-platform-business/issues/28) uses Codechuman Student identity and Auth through its clients. That authentication is an existing platform dependency, not permission to reuse its bearer outside the intended resource. MCP's OAuth grant lifecycle must coexist with IDE sessions without changing their semantics.

## Proposed acceptance gates (not yet passed)

1. Owner approves resource URI/issuer/client registration strategy, scope naming, grant model and downstream delegation proof. Freeze in Auth-owned versioned contracts and matching Gateway/MCP consumer contracts; preserve existing frontend/IDE login and refresh behavior.
2. Targeted RED→GREEN Auth unit/HTTP tests: PKCE verifier mismatch, exact redirect mismatch, code reuse/expiry, client or resource mismatch, wrong issuer/audience, missing scope, consent denial, role change, refresh replay, grant revoke and absence of cross-client token use.
3. Isolated MCP adapter denial tests: forged headers/actor, no bearer, foreign Student, hidden-test/answer projection, unsafe tool and prompt-injection escalation. Confirm absence of secret logging and leaking error detail.
4. Real Auth/RBAC + MCP client connection against disposable infrastructure after owner-authorized runtime gate; record actual tool/client/spec version, negative and positive receipts. No live or shared database, migration or deployment authorization is inferred from this proposal.

**Current result:** contract research only; Auth OAuth implementation, Gateway `/mcp`, MCP adapter, consent UI, migrations, real client connection and runtime checks all **NOT_IMPLEMENTED / NOT_RUN**. Do not label MCP-00 GREEN based on this proposal.
