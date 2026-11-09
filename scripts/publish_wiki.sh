#!/usr/bin/env bash
# Copies docs/wiki/*.md to the GitHub wiki repository. Dry run by default: shows what would change. Add --push to publish.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIGIN="$(git -C "$ROOT" remote get-url origin)"
WIKI="${ORIGIN%.git}.wiki.git"
TMP="$(mktemp -d)"
git clone --depth 1 "$WIKI" "$TMP/wiki" || { echo "Could not clone $WIKI. Enable the Wiki in the repo settings and create the first page once."; exit 1; }
cp "$ROOT"/docs/wiki/*.md "$TMP/wiki/"; rm -f "$TMP/wiki/README.md"
git -C "$TMP/wiki" add -A
git -C "$TMP/wiki" status --short
if [ "${1:-}" = "--push" ]; then
  git -C "$TMP/wiki" commit -m "docs: update wiki" && git -C "$TMP/wiki" push
else
  echo "Dry run. Re-run with --push to publish."
fi
