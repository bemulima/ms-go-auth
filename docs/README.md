# Documentation index

This repository owns auth architecture and its HTTP, NATS, and database contracts.

- [Architecture](architecture.md)
- [HTTP](http-contract.md)
- [Messaging](messaging-contract.md)
- [Database](database-contract.md)
- [Native development](native-development.md)

- [Verification storage](verification-storage.md)

## Proposals (not active contracts)

- [MCP-00A: external Student MCP authorization](mcp00-external-client-authorization-proposal.md) — design proposal only; no OAuth authorization-server routes are live.
- [MCP-00C1: external grant PKCE/redirect/scope policy](mcp00-external-grant-policy-source.md) — source-only validation; no Auth grant/token issuance or runtime activation.
- [MCP-00C2: external code persistence and single-use redemption](mcp00-external-code-store-source.md) — source-only repository/migration, Auth CI source+schema lifecycle PASS; isolated PostgreSQL data-plane gate proposed separately, not wired into an Auth issuer.
- [MCP-00C3A: dormant authorization-server discovery metadata](mcp00-external-as-metadata-source.md) — source-only RFC 8414 issuer/path and future PKCE-S256 JSON contract; no mounted endpoint or live OAuth issuance.
