#!/bin/bash
echo "=== Mint Net Scanner Status ==="
curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "Backend: OFFLINE"
echo ""; pgrep -af "app.py\|http.server.*9000" || echo "No processes"
