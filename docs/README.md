# Documentation index

This repository owns auth architecture and its HTTP, NATS, and database contracts.

- [Architecture](architecture.md)
- [HTTP](http-contract.md)
- [Notification verified recipient (disabled by default)](notification-recipient-v1.md)
- [Mentor HTTP authority (disabled by default)](mentor-http-authority.md)
- [Mentor pure source composition](mentor-composition.md)
- [Mentor executable runtime wiring (explicit opt-in)](mentor-runtime.md)
- [Messaging](messaging-contract.md)
- [Database](database-contract.md)
- [Native development](native-development.md)

- [Verification storage](verification-storage.md)

## Proposals (not active contracts)

- [MCP-00A: external Student MCP authorization](mcp00-external-client-authorization-proposal.md) — design proposal only; no OAuth authorization-server routes are live.
- [MCP-00C1: external grant PKCE/redirect/scope policy](mcp00-external-grant-policy-source.md) — source-only validation; no Auth grant/token issuance or runtime activation.
- [MCP-00C2: external code persistence and single-use redemption](mcp00-external-code-store-source.md) — source-only repository/migration, Auth CI source+schema lifecycle PASS; isolated PostgreSQL data-plane gate proposed separately, not wired into an Auth issuer.
- [MCP-00C3A: dormant authorization-server discovery metadata](mcp00-external-as-metadata-source.md) — source-only RFC 8414 issuer/path and future PKCE-S256 JSON contract; no mounted endpoint or live OAuth issuance.
- [MCP-00C3B: dormant post-code token exchange intent](mcp00-external-token-exchange-source.md) — source-only single-use code redemption followed by fresh Auth/RBAC grant readback; no token signing or live OAuth endpoint.
- [MCP-00C3C: Auth-owned PostgreSQL grant readback](mcp00-external-auth-grant-readback-source.md) — source-only persisted account/client/consent status and exact scopes, checked in disposable PostgreSQL; signed RBAC composition remains unimplemented.
- [MCP-00C3D2: Auth-signed RBAC Student role request/readback](mcp00-external-rbac-role-readback-source.md) — source-only signed proof and strict signed role decision verification; no scopes, token issuance or service wiring.
- [MCP-00C3D4B: Auth-signed RBAC Student scopes request/readback](mcp00-external-rbac-scopes-readback-source.md) — dormant exact read-only proof and signed subset verifier; grant composition and runtime remain disabled.

- [MCP-53 Student browser OAuth read scopes](mcp53-browser-authorize-source.md) — V0 issuer extended to the three existing, independently consented and RBAC-signed Student read scopes. Write scopes remain denied; source tests NOT_RUN for this extension.
- [MCP-53 private learning scope ceiling](mcp53-private-learning-scopes.md) — distinct default-OFF `knowledge:read` and `lessons:read`, no automatic grants or runtime activation.

