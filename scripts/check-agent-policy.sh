#!/bin/sh
set -eu
required_files="AGENTS.md .ai/manifest.yaml .ai/template.yaml .ai/rules/common.md .ai/service.yaml .ai/architecture.yaml .ai/commands.yaml .ai/contracts/http.yaml .ai/contracts/messaging.yaml .ai/contracts/database.yaml .ai/agents/coder.md .ai/agents/backend-coder.md .ai/agents/migration-agent.md .ai/agents/reviewer.md .ai/workflows/bugfix.yaml .ai/workflows/implement-feature.yaml .ai/workflows/refactor.yaml .ai/workflows/review.yaml .ai/workflows/issue-delivery.yaml docs/README.md docs/architecture.md docs/http-contract.md docs/messaging-contract.md docs/database-contract.md"
for policy_file in $required_files; do test -f "$policy_file" || { echo "agent-policy: missing $policy_file" >&2; exit 1; }; done
obsolete_paths='prom''pts/|prom''ps/|jour''nal/|microservices/wi''ki|/wi''ki/|/Users/marat/Developments'
if grep -R -n -E "$obsolete_paths" AGENTS.md .ai docs README.md 2>/dev/null; then echo "agent-policy: obsolete external knowledge reference found" >&2; exit 1; fi
echo "agent-policy: ok"
