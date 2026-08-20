#!/usr/bin/env bash
set -euo pipefail
if ! command -v unshare >/dev/null 2>&1; then
  echo "unshare is required" >&2
  exit 1
fi
unshare --user --map-root-user --net env HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= NO_PROXY= cargo test -p agentark-app --test m0_end_to_end
