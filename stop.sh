#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$DIR/backend.pid"  ] && kill "$(cat "$DIR/backend.pid")"  2>/dev/null || true
[ -f "$DIR/frontend.pid" ] && kill "$(cat "$DIR/frontend.pid")" 2>/dev/null || true
for port in 8000 9000; do fuser -k "${port}/tcp" 2>/dev/null || true; done
echo "✔ Mint Net Scanner stopped"
