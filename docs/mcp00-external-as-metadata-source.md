# MCP-00C3A: proposed Auth authorization-server metadata (source-only)

Parent: [Codechuman MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).

Status: **DORMANT / NOT PUBLISHED**. This change adds only a pure metadata
builder and tests in `internal/usecase`. No `/.well-known/*` HTTP route, issuer,
OAuth authorize/token endpoint, registration endpoint, secret, key, Gateway
route, database migration, token issuance or deployment is added or enabled.

## Contract preview, not a live endpoint

`BuildMCPExternalASMetadata` takes explicit prospective public URLs and a
scoped allowlist. It rejects all requests by default (`PublicationApproved=false`)
and returns the same `ErrMCPExternalDenied` for invalid input. Only test fixtures
set `PublicationApproved=true` to inspect the intended future JSON shape. That
flag is **not** sufficient authorization to mount discovery: separately verify
that both real Auth endpoints, consent/client validation, token signing,
audience enforcement and the HTTP edge are implemented and approved.

For an illustrative, **non-production** issuer `https://auth.example.test/oauth`,
the well-known discovery path under [RFC 8414 section 3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3) is:

```
/.well-known/oauth-authorization-server/oauth
```

The future JSON model has exactly these fields:

```json
{
  "issuer": "https://auth.example.test/oauth",
  "authorization_endpoint": "https://auth.example.test/oauth/authorize",
  "token_endpoint": "https://auth.example.test/oauth/token",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "scopes_supported": ["courses:read", "lessons:read"]
}
```

This is a future **public-client** authorization-code + PKCE-S256 profile;
implement and verify token exchange without a shared secret before ever
publishing `token_endpoint_auth_methods_supported: ["none"]`. The scope names
shown here are test fixture examples, not a production scope decision.
No refresh-token grant, DCR `registration_endpoint`, revocation,
introspection, JWKS URL or Client ID Metadata Document support is claimed.
Avoid advertising a capability before its implementation and contract gate.

## Strict first-party URL policy

- The issuer is a canonical, absolute HTTPS URL with no credentials, query,
  fragment, ambiguous dot segment, duplicate separator or encoded path segment.
- Authorization and token endpoints are distinct, absolute HTTPS URLs with
  non-root paths. They must have the **exact same authority** as the issuer;
  this is a narrow Codechuman security policy, not a general RFC requirement.
- RFC 8414 inserts the well-known suffix **before** any issuer path, and neither
  future endpoint may collide with that path.
- Scopes must be nonempty, distinct, explicitly configured tokens; no wildcard.
  The output copies the scope array so a mutated config cannot change it.

Fail-closed tests cover disabled publication, foreign host, HTTP downgrade,
userinfo, URL normalization, queries/fragments, encoded paths, same endpoints,
invalid scopes, and exact JSON schema. No real Auth/Gateway runtime test is
claimed by this source-only unit slice.

## Decisions before any HTTP activation

1. Owner freezes canonical public Auth issuer and matching Gateway/MCP
   protected-resource URI; the current example domain is a placeholder.
2. Owner freezes external client identity mechanism (verified Client ID
   Metadata Documents and/or pre-registration) and redirect rules.
3. Auth implements the real authorization+consent browser flow and
   token endpoint, token audience/issuer binding, grant revocation and
   token-endpoint auth policy, then exercises HTTP tests on a disposable stack.
4. Only after a separate approved readiness gate, register and serve the exact
   well-known path and synchronize Auth/MCP/Gateway contracts; no accidental
   effect on existing frontend/IDE Google/GitHub login or CAT business logic.

See [MCP-00A design proposal](mcp00-external-client-authorization-proposal.md)
for the broader threat and ownership decisions. The published source-only
code store is not a complete OAuth authorization server.
