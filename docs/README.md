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
- [MCP-00C2: external code persistence and single-use redemption](mcp00-external-code-store-source.md) — source-only repository/migration; **NOT_RUN** and not wired.
