#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  MINT NET SCANNER v3.0 — Universal Self-Healing Auto-Launch Installer
#  Supports: Ubuntu/Debian, CentOS/RHEL/Fedora, Arch, Alpine, Chromebook
#            (Crostini), Raspberry Pi, WSL2, macOS
#
#  FORCED ROOT: Automatically elevates via sudo, installs polkit rules,
#  sets SUID/capabilities on Python so ARP scan + packet capture ALWAYS work.
#
#  Usage: bash install.sh   (no sudo prefix needed)
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

if [ -t 1 ]; then
  R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
  C='\033[0;36m'; B='\033[1m'; N='\033[0m'
else R=''; G=''; Y=''; C=''; B=''; N=''; fi

STEP=0
info()    { STEP=$((STEP+1)); echo -e "${C}[${STEP}]${N} $*"; }
ok()      { echo -e "${G}  ✔${N} $*"; }
warn()    { echo -e "${Y}  ⚠${N}  $*"; }
die()     { echo -e "${R}  ✘ FATAL:${N} $*" >&2; exit 1; }
section() { echo -e "\n${B}── $* ─────────────────────────────────────────${N}"; }

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$INSTALL_DIR/install.log"
exec > >(tee -a "$LOG") 2>&1

echo -e "${G}"
echo "  ███╗   ███╗██╗███╗   ██╗████████╗    ███╗   ██╗███████╗████████╗"
echo "  ████╗ ████║██║████╗  ██║╚══██╔══╝    ████╗  ██║██╔════╝╚══██╔══╝"
echo "  ██╔████╔██║██║██╔██╗ ██║   ██║       ██╔██╗ ██║█████╗     ██║   "
echo "  ██║╚██╔╝██║██║██║╚██╗██║   ██║       ██║╚██╗██║██╔══╝     ██║   "
echo "  ██║ ╚═╝ ██║██║██║ ╚████║   ██║       ██║ ╚████║███████╗   ██║   "
echo "  ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═══╝╚══════╝   ╚═╝  "
echo -e "${N}"
echo -e "  ${C}v3.0 — Universal Self-Healing Installer with Force-Root${N}"
echo "  Install dir: $INSTALL_DIR  |  Log: $LOG"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# 1. FORCE ROOT — multiple escalation strategies
# ══════════════════════════════════════════════════════════════════════════════
section "Force Root Escalation"

SUDO=""
if [ "$EUID" -eq 0 ]; then
  ok "Already root"
else
  # Strategy 1: sudo
  if command -v sudo &>/dev/null; then
    if sudo -n true 2>/dev/null; then
      SUDO="sudo"; ok "sudo (passwordless) available"
    elif sudo -v 2>/dev/null; then
      SUDO="sudo"; ok "sudo authenticated"
    fi
  fi
  # Strategy 2: su fallback
  if [ -z "$SUDO" ] && command -v su &>/dev/null; then
    warn "sudo failed — trying su. Enter root password:"
    su -c "bash '$INSTALL_DIR/install.sh'" && exit 0 || true
  fi
  # Strategy 3: pkexec (graphical sudo)
  if [ -z "$SUDO" ] && command -v pkexec &>/dev/null; then
    SUDO="pkexec"; ok "pkexec available"
  fi
  [ -z "$SUDO" ] && warn "No privilege escalation found — some features may be limited"
fi

# Keep sudo alive in background
if [ "$SUDO" = "sudo" ]; then
  ( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
  SUDO_KA=$!
  trap "kill $SUDO_KA 2>/dev/null; exit" EXIT INT TERM
fi

# ══════════════════════════════════════════════════════════════════════════════
# 2. PLATFORM DETECTION
# ══════════════════════════════════════════════════════════════════════════════
section "Platform Detection"

OS_TYPE=""; PKG_MGR=""; SYSTEMD=false; CHROMEBOOK=false; WSL=false; MACOS=false

if [ "$(uname -s)" = "Darwin" ]; then
  OS_TYPE="macos"; MACOS=true; PKG_MGR="brew"
  ok "macOS detected"
else
  grep -qiE "microsoft|wsl" /proc/version 2>/dev/null && WSL=true && warn "WSL2 detected"
  [ -f /etc/.cros_milestone ] || grep -qi "cros" /proc/version 2>/dev/null && CHROMEBOOK=true && ok "Chromebook/Crostini detected"

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
      ubuntu|debian|linuxmint|pop|elementary|kali|parrot|zorin|raspbian)
        OS_TYPE="debian"; PKG_MGR="apt" ;;
      centos|rhel|almalinux|rocky|ol) OS_TYPE="rhel"
        command -v dnf &>/dev/null && PKG_MGR="dnf" || PKG_MGR="yum" ;;
      fedora)  OS_TYPE="fedora"; PKG_MGR="dnf" ;;
      arch|manjaro|garuda|endeavouros) OS_TYPE="arch"; PKG_MGR="pacman" ;;
      opensuse*|sles) OS_TYPE="suse"; PKG_MGR="zypper" ;;
      alpine)  OS_TYPE="alpine"; PKG_MGR="apk" ;;
      *)       for m in apt dnf yum pacman apk zypper; do command -v $m &>/dev/null && PKG_MGR=$m && break; done
               OS_TYPE="unknown" ;;
    esac
    ok "OS: ${PRETTY_NAME:-$ID} | PKG: $PKG_MGR"
  fi
  command -v systemctl &>/dev/null && $SUDO systemctl list-units &>/dev/null 2>&1 && SYSTEMD=true
fi

# ══════════════════════════════════════════════════════════════════════════════
# 3. PACKAGE INSTALLER HELPERS
# ══════════════════════════════════════════════════════════════════════════════
try_install() {
  for p in "$@"; do
    case "$PKG_MGR" in
      apt)    $SUDO apt-get install -y -qq "$p" 2>/dev/null && ok "$p" && return 0 ;;
      dnf|yum) $SUDO $PKG_MGR install -y -q "$p" 2>/dev/null && ok "$p" && return 0 ;;
      pacman) $SUDO pacman -S --noconfirm --needed "$p" 2>/dev/null && ok "$p" && return 0 ;;
      apk)    $SUDO apk add --no-cache "$p" 2>/dev/null && ok "$p" && return 0 ;;
      zypper) $SUDO zypper install -y "$p" 2>/dev/null && ok "$p" && return 0 ;;
      brew)   brew install "$p" 2>/dev/null && ok "$p" && return 0 ;;
    esac
  done
  warn "Could not install: $*"; return 1
}

pip_install() {
  local pkg="$1"
  "$VENV_PIP" install -q "$pkg" 2>/dev/null && ok "pip: $pkg" && return 0
  $SUDO "$VENV_PIP" install -q "$pkg" 2>/dev/null && ok "pip(sudo): $pkg" && return 0
  python3 -m pip install -q --break-system-packages "$pkg" 2>/dev/null && ok "pip(sys): $pkg" && return 0
  pip3 install -q "$pkg" 2>/dev/null && ok "pip3: $pkg" && return 0
  warn "pip failed: $pkg"; return 1
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. SYSTEM PACKAGES
# ══════════════════════════════════════════════════════════════════════════════
section "System Packages"

case "$PKG_MGR" in
  apt)    $SUDO apt-get update -qq 2>/dev/null || true ;;
  dnf|yum) $SUDO $PKG_MGR makecache -q 2>/dev/null || true ;;
  pacman) $SUDO pacman -Sy --noconfirm 2>/dev/null || true ;;
  apk)    $SUDO apk update 2>/dev/null || true ;;
  brew)   brew update 2>/dev/null || true ;;
esac

command -v python3 &>/dev/null || try_install python3 python
PYTHON=$(command -v python3 || command -v python || die "Python not found")
ok "Python: $($PYTHON --version)"

$PYTHON -m pip --version &>/dev/null 2>&1 || {
  case "$PKG_MGR" in
    apt)     try_install python3-pip ;;
    dnf|yum) try_install python3-pip ;;
    pacman)  try_install python-pip ;;
    apk)     try_install py3-pip ;;
    *)       curl -sS https://bootstrap.pypa.io/get-pip.py | $PYTHON ;;
  esac
}

# venv
$PYTHON -m venv --help &>/dev/null 2>&1 || {
  PV=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
  try_install "python${PV}-venv" python3-venv python3-virtualenv
}

# Network tools
case "$PKG_MGR" in
  apt)    try_install nmap tcpdump libpcap-dev tshark net-tools iproute2 wireless-tools curl libcap2-bin ;;
  dnf|yum) try_install nmap tcpdump libpcap-devel wireshark-cli net-tools iproute libcap curl ;;
  pacman) try_install nmap tcpdump libpcap wireshark-cli net-tools iproute2 libcap curl ;;
  apk)    try_install nmap tcpdump libpcap-dev tshark net-tools iproute2 libcap curl ;;
  brew)   try_install nmap libpcap wireshark curl ;;
  *)      try_install nmap tcpdump curl ;;
esac

# wifi tools for SSID detection
case "$PKG_MGR" in
  apt)    try_install wireless-tools wpasupplicant iw 2>/dev/null || true ;;
  dnf|yum) try_install wireless-tools iw 2>/dev/null || true ;;
  pacman) try_install wireless_tools iw 2>/dev/null || true ;;
  apk)    try_install wireless-tools iw 2>/dev/null || true ;;
esac

# supervisor fallback
$SUDO command -v supervisord &>/dev/null 2>/dev/null || try_install supervisor 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════════
# 5. PYTHON VIRTUALENV
# ══════════════════════════════════════════════════════════════════════════════
section "Python Virtualenv"

VENV="$INSTALL_DIR/backend/.venv"
[ -d "$VENV" ] && ! "$VENV/bin/python" --version &>/dev/null 2>&1 && rm -rf "$VENV"

if [ ! -d "$VENV" ]; then
  $PYTHON -m venv "$VENV" 2>/dev/null || $PYTHON -m virtualenv "$VENV" 2>/dev/null || die "Cannot create venv"
fi

VENV_PYTHON="$VENV/bin/python"
VENV_PIP="$VENV/bin/pip"
"$VENV_PIP" install -q --upgrade pip setuptools wheel 2>/dev/null || true
ok "Virtualenv: $VENV"

# ══════════════════════════════════════════════════════════════════════════════
# 6. PYTHON PACKAGES
# ══════════════════════════════════════════════════════════════════════════════
section "Python Packages"

for pkg in "fastapi==0.111.0" "uvicorn[standard]" "psutil" "pydantic"; do
  pip_install "$pkg" || die "Cannot install: $pkg"
done
pip_install "scapy"       || warn "scapy missing — ARP/capture limited"
pip_install "python-nmap" || warn "python-nmap missing — port scan limited"
pip_install "requests"    || warn "requests missing"
pip_install "pyshark"     || true

# ══════════════════════════════════════════════════════════════════════════════
# 7. FORCE-GRANT RAW SOCKET CAPABILITIES (all strategies)
# ══════════════════════════════════════════════════════════════════════════════
section "Force-Grant Raw Socket Capabilities"

grant_caps() {
  local bin="$1"
  [ -f "$bin" ] || return
  info "Granting caps to $bin"
  # Method 1: setcap (preferred — no SUID needed)
  if command -v setcap &>/dev/null; then
    $SUDO setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$bin" 2>/dev/null \
      && ok "setcap granted: $bin" && return
  fi
  # Method 2: SUID bit (fallback for systems without setcap)
  $SUDO chmod u+s "$bin" 2>/dev/null && ok "SUID set: $bin" && return
  warn "Could not grant caps to $bin"
}

grant_caps "$VENV_PYTHON"
grant_caps "$(readlink -f "$VENV_PYTHON" 2>/dev/null || true)"
grant_caps "$(command -v python3 2>/dev/null || true)"
grant_caps "$(command -v tcpdump 2>/dev/null || true)"
grant_caps "$(command -v dumpcap 2>/dev/null || true)"
grant_caps "$(command -v nmap 2>/dev/null || true)"

# Install polkit rule so daemon can run without password prompt
if command -v pkexec &>/dev/null && [ -d /usr/share/polkit-1/rules.d ]; then
  $SUDO tee /usr/share/polkit-1/rules.d/50-mint-net.rules > /dev/null << 'EOF'
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.policykit.exec" &&
      action.lookup("program").indexOf("mint") !== -1) {
    return polkit.Result.YES;
  }
});
EOF
  ok "polkit rule installed"
fi

# /etc/sudoers.d entry so start.sh never asks for password
CURRENT_USER="${SUDO_USER:-$USER}"
if [ -d /etc/sudoers.d ] && [ -n "$CURRENT_USER" ]; then
  $SUDO tee /etc/sudoers.d/mint-net-scanner > /dev/null << EOF
# Mint Net Scanner — passwordless execution
$CURRENT_USER ALL=(ALL) NOPASSWD: $VENV_PYTHON $INSTALL_DIR/backend/app.py
$CURRENT_USER ALL=(ALL) NOPASSWD: $VENV_PYTHON
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/iptables
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables
EOF
  $SUDO chmod 440 /etc/sudoers.d/mint-net-scanner 2>/dev/null || true
  ok "sudoers.d entry created for $CURRENT_USER"
fi

# Add user to relevant groups
for grp in wireshark netdev pcap; do
  getent group "$grp" &>/dev/null && $SUDO usermod -aG "$grp" "${SUDO_USER:-$USER}" 2>/dev/null && ok "Added to group: $grp" || true
done

# ══════════════════════════════════════════════════════════════════════════════
# 8. AUTO-CONFIGURATION (detect interface, subnet, SSID)
# ══════════════════════════════════════════════════════════════════════════════
section "Auto-Configuration"

DEFAULT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[\d.]+' \
  || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
IFS='.' read -r i1 i2 i3 _ <<< "$LOCAL_IP"
AUTO_SUBNET="${i1}.${i2}.${i3}.0/24"

# SSID detection (multiple methods)
SSID="Unknown Network"
for cmd in \
  "iwgetid -r 2>/dev/null" \
  "iw dev 2>/dev/null | grep -oP 'ssid \K.*' | head -1" \
  "nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2" \
  "wpa_cli -i $DEFAULT_IFACE status 2>/dev/null | grep ssid= | cut -d= -f2"; do
  result=$(eval "$cmd" 2>/dev/null | tr -d '\n')
  [ -n "$result" ] && [ "$result" != " " ] && SSID="$result" && break
done

ok "Interface : $DEFAULT_IFACE"
ok "Local IP  : $LOCAL_IP"
ok "Subnet    : $AUTO_SUBNET"
ok "SSID      : $SSID"

cat > "$INSTALL_DIR/backend/.env" << EOF
MINT_INTERFACE=$DEFAULT_IFACE
MINT_SUBNET=$AUTO_SUBNET
MINT_LOCAL_IP=$LOCAL_IP
MINT_SSID=$SSID
MINT_HOST=0.0.0.0
MINT_PORT=8000
MINT_FRONTEND_PORT=9000
EOF
ok ".env written"

# Open firewall ports
command -v ufw &>/dev/null && $SUDO ufw status 2>/dev/null | grep -q "active" && {
  $SUDO ufw allow 8000/tcp 2>/dev/null; $SUDO ufw allow 9000/tcp 2>/dev/null; ok "ufw rules added"
}
command -v firewall-cmd &>/dev/null && {
  $SUDO firewall-cmd --permanent --add-port=8000/tcp 2>/dev/null
  $SUDO firewall-cmd --permanent --add-port=9000/tcp 2>/dev/null
  $SUDO firewall-cmd --reload 2>/dev/null; ok "firewalld rules added"
}
$SUDO iptables -I INPUT -p tcp --dport 8000 -j ACCEPT 2>/dev/null || true
$SUDO iptables -I INPUT -p tcp --dport 9000 -j ACCEPT 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════════
# 9. PROCESS MANAGER
# ══════════════════════════════════════════════════════════════════════════════
section "Process Manager Setup"

BACKEND_CMD="$VENV_PYTHON $INSTALL_DIR/backend/app.py"
FRONTEND_CMD="$VENV_PYTHON -m http.server 9000 --directory $INSTALL_DIR/frontend"

setup_systemd() {
  $SUDO tee /etc/systemd/system/mint-backend.service > /dev/null << EOF
[Unit]
Description=Mint Net Scanner Backend
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=10

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/backend
EnvironmentFile=$INSTALL_DIR/backend/.env
ExecStart=$BACKEND_CMD
Restart=always
RestartSec=2
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
  $SUDO tee /etc/systemd/system/mint-frontend.service > /dev/null << EOF
[Unit]
Description=Mint Net Scanner Frontend
After=mint-backend.service
Wants=mint-backend.service

[Service]
Type=simple
User=root
ExecStart=$FRONTEND_CMD
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable mint-backend mint-frontend 2>/dev/null
  $SUDO systemctl restart mint-backend && ok "mint-backend started" || warn "mint-backend start failed"
  $SUDO systemctl restart mint-frontend && ok "mint-frontend started" || warn "mint-frontend start failed"
}

setup_supervisor() {
  command -v supervisord &>/dev/null || pip_install supervisor || return 1
  SCFD=""
  for d in /etc/supervisor/conf.d /etc/supervisord.d /usr/local/etc/supervisor.d; do
    [ -d "$d" ] && SCFD="$d" && break
  done
  [ -z "$SCFD" ] && $SUDO mkdir -p /etc/supervisor/conf.d && SCFD="/etc/supervisor/conf.d"
  $SUDO tee "$SCFD/mint.conf" > /dev/null << EOF
[program:mint-backend]
command=$BACKEND_CMD
directory=$INSTALL_DIR/backend
autostart=true
autorestart=true
startretries=10
user=root
stdout_logfile=/var/log/mint-backend.log
stderr_logfile=/var/log/mint-backend.log

[program:mint-frontend]
command=$FRONTEND_CMD
autostart=true
autorestart=true
startretries=10
user=root
stdout_logfile=/var/log/mint-frontend.log
EOF
  pgrep supervisord &>/dev/null \
    && { $SUDO supervisorctl reread; $SUDO supervisorctl update; } \
    || $SUDO supervisord -c /etc/supervisor/supervisord.conf 2>/dev/null \
    || $SUDO supervisord 2>/dev/null || return 1
  ok "supervisor configured"
}

setup_rc_local() {
  RC="/etc/rc.local"
  [ -f "$RC" ] || printf '#!/bin/sh\nexit 0\n' | $SUDO tee "$RC" > /dev/null
  $SUDO chmod +x "$RC"
  $SUDO sed -i '/exit 0/d' "$RC"
  $SUDO tee -a "$RC" > /dev/null << EOF
nohup $BACKEND_CMD  > /var/log/mint-backend.log  2>&1 &
nohup $FRONTEND_CMD > /var/log/mint-frontend.log 2>&1 &
exit 0
EOF
  ok "rc.local updated"
}

LAUNCH_METHOD=""
$SYSTEMD && setup_systemd && LAUNCH_METHOD="systemd"
[ -z "$LAUNCH_METHOD" ] && setup_supervisor && LAUNCH_METHOD="supervisor"
[ -z "$LAUNCH_METHOD" ] && { setup_rc_local; LAUNCH_METHOD="rc.local"; }
[ -z "$LAUNCH_METHOD" ] && {
  (crontab -l 2>/dev/null | grep -v mint-
   echo "@reboot $BACKEND_CMD >> /var/log/mint-backend.log 2>&1"
   echo "@reboot $FRONTEND_CMD >> /var/log/mint-frontend.log 2>&1") | crontab -
  LAUNCH_METHOD="crontab"
}
ok "Launch method: $LAUNCH_METHOD"

# ══════════════════════════════════════════════════════════════════════════════
# 10. IMMEDIATE START
# ══════════════════════════════════════════════════════════════════════════════
section "Immediate Launch"

for port in 8000 9000; do
  fuser -k "${port}/tcp" 2>/dev/null || lsof -ti ":$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
done
sleep 1

# Start backend as root (forced)
info "Starting backend (root)..."
$SUDO nohup $BACKEND_CMD > /var/log/mint-backend.log 2>&1 &
BPID=$!
echo "$BPID" > "$INSTALL_DIR/backend.pid" 2>/dev/null || true
ok "Backend PID $BPID"

# Start frontend
info "Starting frontend..."
nohup $FRONTEND_CMD > /var/log/mint-frontend.log 2>&1 &
FPID=$!
echo "$FPID" > "$INSTALL_DIR/frontend.pid" 2>/dev/null || true
ok "Frontend PID $FPID"

# ══════════════════════════════════════════════════════════════════════════════
# 11. HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════
section "Health Check"
info "Waiting for API..."
HEALTHY=false
for i in $(seq 1 30); do
  sleep 2; echo -n "."
  curl -sf "http://localhost:8000/health" > /tmp/mint-health.json 2>/dev/null && HEALTHY=true && break
done
echo ""

if $HEALTHY; then
  ok "API healthy!"
  $PYTHON -c "
import json,sys
d=json.load(open('/tmp/mint-health.json'))
print(f'    Root     : {\"✔\" if d.get(\"running_as_root\") else \"✘\"}')
print(f'    Scapy    : {\"✔\" if d.get(\"scapy\") else \"✘\"}')
print(f'    Nmap     : {\"✔\" if d.get(\"nmap\") else \"✘\"}')
print(f'    Sniffer  : {\"✔ ACTIVE\" if d.get(\"sniffer_active\") else \"starting...\"}')
print(f'    Interface: {d.get(\"default_interface\",\"?\")}')
print(f'    SSID     : {d.get(\"ssid\",\"?\")}')
print(f'    Local IP : {d.get(\"local_ip\",\"?\")}')
" 2>/dev/null || true
else
  warn "API not responding — check: tail -40 /var/log/mint-backend.log"
  tail -20 /var/log/mint-backend.log 2>/dev/null || true
fi

# ══════════════════════════════════════════════════════════════════════════════
# 12. AUTO-OPEN BROWSER
# ══════════════════════════════════════════════════════════════════════════════
section "Opening Browser"

URL="http://$LOCAL_IP:9000"
$CHROMEBOOK && command -v garcon-url-handler &>/dev/null && { garcon-url-handler "$URL" & ok "Chromebook browser opened"; } || \
$MACOS && { open "$URL" & ok "macOS browser opened"; } || \
$WSL && { cmd.exe /c start "$URL" 2>/dev/null & ok "Windows browser opened"; } || \
{ for b in xdg-open chromium-browser google-chrome firefox; do
    command -v "$b" &>/dev/null && { "$b" "$URL" &>/dev/null & ok "Browser: $b"; break; }
  done; } || warn "Visit manually: $URL"

# ══════════════════════════════════════════════════════════════════════════════
# 13. MANAGEMENT SCRIPTS
# ══════════════════════════════════════════════════════════════════════════════
section "Writing Management Scripts"

cat > "$INSTALL_DIR/start.sh" << SEOF
#!/bin/bash
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
for p in 8000 9000; do fuser -k "\${p}/tcp" 2>/dev/null || true; done; sleep 1
sudo nohup "$VENV_PYTHON" "\$DIR/backend/app.py" > /var/log/mint-backend.log 2>&1 &
echo \$! > "\$DIR/backend.pid"
nohup "$VENV_PYTHON" -m http.server 9000 --directory "\$DIR/frontend" > /var/log/mint-frontend.log 2>&1 &
echo \$! > "\$DIR/frontend.pid"
sleep 2 && echo "✔ Mint Net Scanner → http://localhost:9000"
SEOF

cat > "$INSTALL_DIR/stop.sh" << SEOF
#!/bin/bash
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
[ -f "\$DIR/backend.pid"  ] && kill "\$(cat "\$DIR/backend.pid")"  2>/dev/null
[ -f "\$DIR/frontend.pid" ] && kill "\$(cat "\$DIR/frontend.pid")" 2>/dev/null
for p in 8000 9000; do fuser -k "\${p}/tcp" 2>/dev/null || true; done
echo "✔ Mint Net Scanner stopped"
SEOF

cat > "$INSTALL_DIR/status.sh" << 'SEOF'
#!/bin/bash
echo "=== Mint Net Scanner Status ==="
curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "Backend: OFFLINE"
echo ""; pgrep -af "app.py\|http.server.*9000" || echo "No processes"
SEOF

chmod +x "$INSTALL_DIR/start.sh" "$INSTALL_DIR/stop.sh" "$INSTALL_DIR/status.sh"
ok "start.sh / stop.sh / status.sh written"

# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${G}╔══════════════════════════════════════════════════════════════╗${N}"
echo -e "${G}║        Mint Net Scanner v3.0 — Installation Complete!        ║${N}"
echo -e "${G}╠══════════════════════════════════════════════════════════════╣${N}"
echo -e "${G}║${N}  Dashboard   →  ${B}http://$LOCAL_IP:9000${N}"
echo -e "${G}║${N}  API         →  http://$LOCAL_IP:8000"
echo -e "${G}║${N}  Auto-launch →  ${B}$LAUNCH_METHOD${N} (survives reboots)"
echo -e "${G}║${N}  Raw sockets →  Force-granted via setcap + sudoers.d"
echo -e "${G}║${N}"
echo -e "${G}║${N}  bash start.sh   bash stop.sh   bash status.sh"
echo -e "${G}╚══════════════════════════════════════════════════════════════╝${N}"
echo ""
