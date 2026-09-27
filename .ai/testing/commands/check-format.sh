#!/usr/bin/env bash
set -euo pipefail

formatted="$(git ls-files -z -- '*.go' | xargs -0 gofmt -l)"
if [[ -n "$formatted" ]]; then
  printf '%s\n' "$formatted" >&2
  exit 1
fi
