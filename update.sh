#!/usr/bin/env bash
# Pull latest from GitHub and restart
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" && git pull origin main && bash install.sh
