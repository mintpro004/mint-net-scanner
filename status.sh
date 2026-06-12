#!/usr/bin/env bash
echo "══ Mint Net Scanner Status ══════════════════════════"
if curl -sf http://localhost:8000/health | python3 -m json.tool; then
  echo ""
  echo "✔ Dashboard: http://localhost:9000"
else
  echo "✘ Backend OFFLINE — try: bash start.sh"
fi
echo ""
echo "── Processes ──────────────────────────────────────"
pgrep -af "app\.py\|http\.server.*9000" || echo "(none running)"
echo ""
echo "── Last 10 backend log lines ──────────────────────"
tail -10 /var/log/mint-backend.log 2>/dev/null || echo "(no log)"
