#!/usr/bin/env bash
# Mint Net Scanner — start script (auto-generated)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$DIR/backend/.venv/bin/python"
for port in 8000 9000; do
  fuser -k "${port}/tcp" 2>/dev/null || lsof -ti ":${port}" 2>/dev/null | xargs kill -9 2>/dev/null || true
done
sleep 1
sudo nohup bash -c "$VENV_PY $DIR/backend/app.py >> /var/log/mint-backend.log 2>&1" &
echo $! > "$DIR/backend.pid"
nohup bash -c "$VENV_PY -m http.server 9000 --directory $DIR/frontend >> /var/log/mint-frontend.log 2>&1" &
echo $! > "$DIR/frontend.pid"
sleep 2
curl -sf http://localhost:8000/health > /dev/null && echo "✔ Mint Net Scanner running → http://localhost:9000" || echo "⚠ Backend not responding yet — check /var/log/mint-backend.log"
