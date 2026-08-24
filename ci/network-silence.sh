#!/usr/bin/env bash
set -euo pipefail
if ! command -v sudo >/dev/null 2>&1 || ! command -v unshare >/dev/null 2>&1; then
  echo "sudo and unshare are required" >&2
  exit 1
fi
sudo unshare --net env \
  HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= NO_PROXY= \
  CARGO_NET_OFFLINE=true \
  cargo test -p agentark-app --test m0_end_to_end --offline
