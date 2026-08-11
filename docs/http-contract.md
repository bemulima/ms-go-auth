# HTTP contract

The base path defaults to /api/v1. Auth routes are listed in .ai/contracts/http.yaml and internal/adapters/http/api/v1/router.go. Protected routes use JWT middleware. /internal/health is GET.

OAuth start and callback are implemented for registered Google and GitHub providers. Email-change verification accepts the pending flow code as defined by the handler; do not reuse stale wiki payload examples without checking code. Validation errors use the shared JSON error envelope.

Access TTL defaults to 15m and refresh TTL to 720h. These values are configuration defaults, not fixed protocol guarantees.
