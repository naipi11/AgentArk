#!/usr/bin/env bash
set -euo pipefail
if ! command -v sudo >/dev/null 2>&1 || ! command -v unshare >/dev/null 2>&1; then
  echo "sudo and unshare are required" >&2
  exit 1
fi

CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
CARGO_BIN="$CARGO_HOME/bin/cargo"
if [ ! -x "$CARGO_BIN" ]; then
  echo "cargo executable is not available at $CARGO_BIN" >&2
  exit 1
fi

sudo unshare --net env \
  HOME="$HOME" \
  CARGO_HOME="$CARGO_HOME" \
  RUSTUP_HOME="$RUSTUP_HOME" \
  PATH="$CARGO_HOME/bin:$PATH" \
  HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= NO_PROXY= \
  CARGO_NET_OFFLINE=true \
  "$CARGO_BIN" test -p agentark-app --test m0_end_to_end --offline
