#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$DIR/backend.pid"  ] && kill "$(cat "$DIR/backend.pid")"  2>/dev/null
[ -f "$DIR/frontend.pid" ] && kill "$(cat "$DIR/frontend.pid")" 2>/dev/null
for p in 8000 9000; do fuser -k "${p}/tcp" 2>/dev/null || true; done
echo "✔ Mint Net Scanner stopped"
