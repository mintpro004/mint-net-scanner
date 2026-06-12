#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for p in 8000 9000; do fuser -k "${p}/tcp" 2>/dev/null || true; done; sleep 1
sudo nohup "/home/mint/cyber-tools/mint-net-scanner-v3.0/mint-net-scanner/backend/.venv/bin/python" "$DIR/backend/app.py" > /var/log/mint-backend.log 2>&1 &
echo $! > "$DIR/backend.pid"
nohup "/home/mint/cyber-tools/mint-net-scanner-v3.0/mint-net-scanner/backend/.venv/bin/python" -m http.server 9000 --directory "$DIR/frontend" > /var/log/mint-frontend.log 2>&1 &
echo $! > "$DIR/frontend.pid"
sleep 2 && echo "✔ Mint Net Scanner → http://localhost:9000"
