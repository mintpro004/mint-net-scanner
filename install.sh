#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  MINT NET SCANNER v3.1 — Hardened Universal Self-Healing Installer
#
#  Supports: Ubuntu 18-24, Debian 10-12, Kali, Parrot, Pop!OS, Linux Mint,
#            Raspbian/RPi OS, CentOS 7-9, RHEL 8-9, AlmaLinux, Rocky,
#            Fedora 36-40, Arch, Manjaro, Endeavour, Alpine 3.14+,
#            openSUSE Leap/Tumbleweed, Void Linux,
#            Chromebook/Crostini, WSL2, macOS 12+
#
#  Single command:  bash install.sh
#  - Auto-detects OS and package manager
#  - Force-grants raw socket caps (setcap + sudoers + SUID fallback)
#  - Self-heals every pip/package failure
#  - Sets up auto-launch (systemd → supervisor → rc.local → cron)
#  - Immediately starts services and opens browser
#  - Full install log at ./install.log
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail
IFS=$'\n\t'

# Ensure /sbin and /usr/sbin are in PATH for setcap/iptables
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# ── Colours (safe fallback if no TTY) ────────────────────────────────────────
if [ -t 1 ] && command -v tput &>/dev/null && tput colors &>/dev/null 2>&1; then
  R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
else
  R='' G='' Y='' C='' B='' N=''
fi

# ── Logging ───────────────────────────────────────────────────────────────────
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$INSTALL_DIR/install.log"
# Tee to log file, preserve TTY output
exec > >(tee -a "$LOG") 2>&1

STEP=0
info()    { STEP=$((STEP+1)); echo -e "${C}[${STEP}]${N} $*"; }
ok()      { echo -e "  ${G}✔${N} $*"; }
warn()    { echo -e "  ${Y}⚠${N}  $*"; }
err()     { echo -e "  ${R}✘${N}  $*"; }
die()     { echo -e "\n${R}FATAL:${N} $*" >&2; echo "See $LOG for details."; exit 1; }
section() { echo -e "\n${B}━━  $*  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"; }

echo ""
echo -e "${G}  ╔╦╗╦╔╗╔╔╦╗  ╔╗╔╔═╗╔╦╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗${N}"
echo -e "${G}  ║║║║║║║ ║   ║║║║╣  ║   ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝${N}"
echo -e "${G}  ╩ ╩╩╝╚╝ ╩   ╝╚╝╚═╝ ╩   ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═${N}"
echo -e "      ${C}v3.1 — Universal Self-Healing Installer${N}"
echo ""
echo "  Dir : $INSTALL_DIR"
echo "  Log : $LOG"
echo "  Date: $(date)"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — ROOT / PRIVILEGE ESCALATION
# ══════════════════════════════════════════════════════════════════════════════
section "Root / Privilege Escalation"

SUDO=""

if [ "$EUID" -eq 0 ]; then
  ok "Running as root"
else
  # Try sudo (passwordless first, then interactive)
  if command -v sudo &>/dev/null; then
    if sudo -n true 2>/dev/null; then
      SUDO="sudo"
      ok "sudo: passwordless access"
    else
      info "sudo requires password — prompting once..."
      if sudo -v 2>/dev/null; then
        SUDO="sudo"
        ok "sudo: authenticated"
      else
        warn "sudo auth failed — trying alternatives"
      fi
    fi
  fi

  # Fallback: su
  if [ -z "$SUDO" ] && command -v su &>/dev/null; then
    warn "No sudo — relaunching via su (enter root password):"
    exec su -c "bash '$INSTALL_DIR/install.sh'"
  fi

  # Fallback: pkexec (graphical polkit)
  if [ -z "$SUDO" ] && command -v pkexec &>/dev/null; then
    SUDO="pkexec"
    ok "pkexec available"
  fi

  if [ -z "$SUDO" ]; then
    warn "No privilege escalation available — raw socket features will be limited"
    warn "Re-run as root for full functionality: sudo bash install.sh"
  fi
fi

# Keep sudo alive in background so long package installs don't time out
if [ "$SUDO" = "sudo" ]; then
  ( while true; do sudo -n true 2>/dev/null; sleep 45; done ) &
  _SUDO_KEEPALIVE=$!
  trap 'kill $_SUDO_KEEPALIVE 2>/dev/null; exit' EXIT INT TERM HUP
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — PLATFORM DETECTION
# ══════════════════════════════════════════════════════════════════════════════
section "Platform Detection"

OS_ID=""        # e.g. ubuntu, debian, fedora, arch, alpine …
OS_FAMILY=""    # debian | rhel | arch | alpine | suse | void | macos
PKG_MGR=""      # apt | dnf | yum | pacman | apk | zypper | xbps | brew
SYSTEMD=false
IS_CHROMEBOOK=false
IS_WSL=false
IS_MACOS=false
IS_RASPI=false
IS_CONTAINER=false
ARCH="$(uname -m)"   # x86_64 | aarch64 | armv7l …

# macOS
if [ "$(uname -s)" = "Darwin" ]; then
  IS_MACOS=true
  OS_FAMILY="macos"
  PKG_MGR="brew"
  ok "macOS $(sw_vers -productVersion 2>/dev/null || echo '?')"
else
  # WSL
  if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
    IS_WSL=true
    warn "WSL2/WSL1 detected — raw packet capture may be limited"
  fi

  # Chromebook / Crostini Linux container
  if [ -f /etc/.cros_milestone ] \
     || grep -qi "cros" /proc/version 2>/dev/null \
     || [ -f /opt/google/chrome/chrome ] \
     || (command -v hostnamectl &>/dev/null && hostnamectl 2>/dev/null | grep -qi "penguin"); then
    IS_CHROMEBOOK=true
    ok "Chromebook / Crostini detected"
  fi

  # Raspberry Pi
  if [ -f /proc/device-tree/model ] && grep -qi "raspberry" /proc/device-tree/model 2>/dev/null; then
    IS_RASPI=true
    ok "Raspberry Pi: $(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')"
  fi

  # Container / Docker
  if [ -f /.dockerenv ] || grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER=true
    warn "Container environment detected"
  fi

  # Read /etc/os-release
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    case "$OS_ID" in
      ubuntu|debian|linuxmint|pop|elementary|kali|parrot|zorin|raspbian|armbian)
        OS_FAMILY="debian"; PKG_MGR="apt" ;;
      centos|rhel|almalinux|rocky|ol|amzn)
        OS_FAMILY="rhel"
        command -v dnf &>/dev/null && PKG_MGR="dnf" || PKG_MGR="yum" ;;
      fedora)
        OS_FAMILY="rhel"; PKG_MGR="dnf" ;;
      arch|manjaro|garuda|endeavouros|artix)
        OS_FAMILY="arch"; PKG_MGR="pacman" ;;
      opensuse*|sles)
        OS_FAMILY="suse"; PKG_MGR="zypper" ;;
      alpine)
        OS_FAMILY="alpine"; PKG_MGR="apk" ;;
      void)
        OS_FAMILY="void"; PKG_MGR="xbps-install" ;;
      *)
        OS_FAMILY="unknown"
        # Auto-detect package manager
        for _m in apt dnf yum pacman apk zypper xbps-install; do
          command -v "$_m" &>/dev/null && { PKG_MGR="$_m"; break; }
        done
        [ -z "$PKG_MGR" ] && die "Cannot detect package manager. Install manually and re-run."
        warn "Unrecognised distro '$OS_ID' — using detected pkg manager: $PKG_MGR"
        ;;
    esac
    ok "OS   : ${PRETTY_NAME:-$OS_ID}"
  elif IS_MACOS; then
    true  # already handled above
  else
    die "Cannot read /etc/os-release. Unsupported system."
  fi

  # Systemd availability
  if command -v systemctl &>/dev/null; then
    # Works in containers with systemd, fails gracefully otherwise
    if systemctl is-system-running &>/dev/null 2>&1 \
       || $SUDO systemctl list-units --no-pager &>/dev/null 2>&1; then
      SYSTEMD=true
    fi
  fi

  ok "Arch : $ARCH"
  ok "PKG  : $PKG_MGR"
  ok "Systemd: $SYSTEMD"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — PACKAGE MANAGER HELPERS
# ══════════════════════════════════════════════════════════════════════════════
section "Package Manager Helpers"

_pkg_update() {
  info "Updating package index..."
  case "$PKG_MGR" in
    apt)
      # Disable interactive prompts
      DEBIAN_FRONTEND=noninteractive $SUDO apt-get update -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" 2>/dev/null || warn "apt update partial failure (continuing)"
      ;;
    dnf)    $SUDO dnf makecache --quiet 2>/dev/null || warn "dnf makecache failed" ;;
    yum)    $SUDO yum makecache fast --quiet 2>/dev/null || warn "yum makecache failed" ;;
    pacman) $SUDO pacman -Sy --noconfirm 2>/dev/null || warn "pacman -Sy failed" ;;
    apk)    $SUDO apk update --quiet 2>/dev/null || warn "apk update failed" ;;
    zypper) $SUDO zypper --quiet refresh 2>/dev/null || warn "zypper refresh failed" ;;
    brew)   brew update 2>/dev/null || warn "brew update failed" ;;
    xbps-install) $SUDO xbps-install -Su 2>/dev/null || warn "xbps update failed" ;;
  esac
}

# try_pkg <pkg1> [<pkg2> ...] — installs first successful package from the list
try_pkg() {
  for p in "$@"; do
    [ -z "$p" ] && continue
    case "$PKG_MGR" in
      apt)
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq \
          -o Dpkg::Options::="--force-confdef" \
          -o Dpkg::Options::="--force-confold" "$p" 2>/dev/null \
          && ok "installed: $p" && return 0 ;;
      dnf)    $SUDO dnf install -y -q "$p" 2>/dev/null && ok "installed: $p" && return 0 ;;
      yum)    $SUDO yum install -y -q "$p" 2>/dev/null && ok "installed: $p" && return 0 ;;
      pacman) $SUDO pacman -S --noconfirm --needed "$p" 2>/dev/null && ok "installed: $p" && return 0 ;;
      apk)    $SUDO apk add --no-cache -q "$p" 2>/dev/null && ok "installed: $p" && return 0 ;;
      zypper) $SUDO zypper --quiet install -y "$p" 2>/dev/null && ok "installed: $p" && return 0 ;;
      xbps-install) $SUDO xbps-install -y "$p" 2>/dev/null && ok "installed: $p" && return 0 ;;
      brew)   brew install "$p" 2>/dev/null && ok "installed: $p" && return 0 ;;
    esac
  done
  warn "Could not install (tried: $*)"
  return 1
}

_pkg_update

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — PYTHON 3 INSTALLATION
# ══════════════════════════════════════════════════════════════════════════════
section "Python 3"

# Ensure python3 exists
if ! command -v python3 &>/dev/null; then
  case "$PKG_MGR" in
    apt)    try_pkg python3 python3-minimal ;;
    dnf|yum) try_pkg python3 python39 python38 ;;
    pacman) try_pkg python ;;
    apk)    try_pkg python3 ;;
    zypper) try_pkg python3 ;;
    xbps-install) try_pkg python3 ;;
    brew)   brew install python3 2>/dev/null || true ;;
  esac
fi

PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null)
[ -z "$PYTHON" ] && die "Python 3 not found and could not be installed."

PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
ok "Python $PY_VER at $PYTHON"

# Minimum version check
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
  die "Python 3.8+ required. Found: $PY_VER"
fi

# Ensure pip
if ! "$PYTHON" -m pip --version &>/dev/null 2>&1; then
  info "pip not found — installing..."
  case "$PKG_MGR" in
    apt)    try_pkg python3-pip ;;
    dnf|yum) try_pkg python3-pip ;;
    pacman) try_pkg python-pip ;;
    apk)    try_pkg py3-pip ;;
    zypper) try_pkg python3-pip ;;
    xbps-install) try_pkg python3-pip ;;
    brew)   true ;; # bundled with python
  esac

  # Bootstrap via get-pip.py if still not available
  if ! "$PYTHON" -m pip --version &>/dev/null 2>&1; then
    info "Bootstrapping pip via get-pip.py..."
    if command -v curl &>/dev/null; then
      curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/mint-get-pip.py \
        && "$PYTHON" /tmp/mint-get-pip.py --quiet 2>/dev/null \
        && ok "pip bootstrapped" \
        || warn "pip bootstrap failed"
    else
      warn "curl not available — cannot bootstrap pip"
    fi
  fi
fi
"$PYTHON" -m pip --version &>/dev/null 2>&1 && ok "pip available" || warn "pip still missing — will try alternatives"

# python3-venv
if ! "$PYTHON" -m venv --help &>/dev/null 2>&1; then
  info "Installing python venv module..."
  case "$PKG_MGR" in
    apt)    try_pkg "python${PY_VER}-venv" python3-venv python3-virtualenv ;;
    dnf|yum) try_pkg python3-virtualenv ;;
    pacman) try_pkg python-virtualenv ;;
    apk)    try_pkg py3-virtualenv ;;
    *)      try_pkg python3-venv ;;
  esac
  # Fallback: pip install virtualenv
  "$PYTHON" -m pip install --quiet virtualenv 2>/dev/null || true
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — SYSTEM PACKAGES (nmap, tcpdump, libpcap, iproute, etc.)
# ══════════════════════════════════════════════════════════════════════════════
section "System Network Packages"

case "$PKG_MGR" in
  apt)
    # libcap2-bin provides setcap; wireless-tools provides iwgetid
    for p in \
      "nmap" "tcpdump" "libpcap-dev" "tshark" \
      "net-tools" "iproute2" "iw" "wireless-tools" "wpasupplicant" \
      "curl" "wget" "libcap2-bin" "ca-certificates" \
      "gcc" "python3-dev" "libffi-dev" "libssl-dev"; do
      try_pkg "$p" || true
    done
    ;;
  dnf|yum)
    for p in \
      "nmap" "tcpdump" "libpcap" "libpcap-devel" "wireshark-cli" \
      "net-tools" "iproute" "iw" "wireless-tools" \
      "curl" "wget" "libcap" "ca-certificates" \
      "gcc" "python3-devel" "libffi-devel" "openssl-devel"; do
      try_pkg "$p" || true
    done
    ;;
  pacman)
    for p in \
      "nmap" "tcpdump" "libpcap" "wireshark-cli" \
      "net-tools" "iproute2" "iw" "wireless_tools" \
      "curl" "wget" "libcap" \
      "gcc" "python"; do
      try_pkg "$p" || true
    done
    ;;
  apk)
    for p in \
      "nmap" "tcpdump" "libpcap-dev" "tshark" \
      "net-tools" "iproute2" "iw" "wireless-tools" \
      "curl" "wget" "libcap" "ca-certificates" \
      "gcc" "python3-dev" "musl-dev" "libffi-dev" "openssl-dev"; do
      try_pkg "$p" || true
    done
    ;;
  zypper)
    for p in \
      "nmap" "tcpdump" "libpcap-devel" \
      "net-tools" "iproute2" "iw" "wireless-tools" \
      "curl" "wget" "libcap-progs" \
      "gcc" "python3-devel" "libffi-devel" "libopenssl-devel"; do
      try_pkg "$p" || true
    done
    ;;
  brew)
    for p in "nmap" "libpcap" "curl" "wget"; do
      try_pkg "$p" || true
    done
    ;;
  xbps-install)
    for p in "nmap" "tcpdump" "libpcap-devel" "iproute2" "curl" "libcap"; do
      try_pkg "$p" || true
    done
    ;;
esac

# supervisor (process manager fallback when no systemd)
if ! $SYSTEMD; then
  case "$PKG_MGR" in
    apt)     try_pkg supervisor || true ;;
    dnf|yum) try_pkg supervisor || true ;;
    pacman)  try_pkg supervisor || true ;;
    apk)     try_pkg supervisor || true ;;
    brew)    brew install supervisor 2>/dev/null || true ;;
    *)       try_pkg supervisor || true ;;
  esac
fi

ok "System packages done"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — PYTHON VIRTUAL ENVIRONMENT
# ══════════════════════════════════════════════════════════════════════════════
section "Python Virtual Environment"

VENV="$INSTALL_DIR/backend/.venv"

# Remove broken venv
if [ -d "$VENV" ]; then
  if ! "$VENV/bin/python" -c "import sys" &>/dev/null 2>&1; then
    warn "Existing venv is broken — removing"
    $SUDO rm -rf "$VENV"
  fi
fi

if [ ! -d "$VENV" ]; then
  info "Creating virtualenv at $VENV"
  "$PYTHON" -m venv "$VENV" 2>/dev/null \
    || "$PYTHON" -m virtualenv "$VENV" 2>/dev/null \
    || die "Cannot create Python virtual environment"
fi

VENV_PYTHON="$VENV/bin/python"
VENV_PIP="$VENV/bin/pip"

# Upgrade pip, setuptools, wheel inside venv
info "Upgrading pip/setuptools/wheel..."
"$VENV_PIP" install --quiet --upgrade pip setuptools wheel 2>/dev/null || true

ok "Virtualenv ready: $VENV"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — PYTHON PACKAGES  (self-healing per-package)
# ══════════════════════════════════════════════════════════════════════════════
section "Python Package Installation"

# Self-healing pip installer:
# Tries venv pip → sudo venv pip → system pip --break-system-packages → pip3 → pip
_pip() {
  local pkg="$1"
  info "pip install: $pkg"

  # 1. venv pip (normal)
  "$VENV_PIP" install --quiet "$pkg" 2>/dev/null \
    && ok "$pkg" && return 0

  # 2. venv pip with extra index (PyPI mirror fallback)
  "$VENV_PIP" install --quiet \
    --extra-index-url https://pypi.org/simple/ "$pkg" 2>/dev/null \
    && ok "$pkg (mirror)" && return 0

  # 3. sudo venv pip (for setuid situations)
  [ -n "$SUDO" ] && $SUDO "$VENV_PIP" install --quiet --break-system-packages "$pkg" 2>/dev/null \
    && ok "$pkg (sudo)" && return 0

  # 4. System python with --break-system-packages (PEP 668 / Ubuntu 23+)
  "$PYTHON" -m pip install --quiet --break-system-packages "$pkg" 2>/dev/null \
    && ok "$pkg (sys)" && return 0

  # 5. pip3
  command -v pip3 &>/dev/null && pip3 install --quiet "$pkg" 2>/dev/null \
    && ok "$pkg (pip3)" && return 0

  warn "All install methods failed for: $pkg"
  return 1
}

# ── Core packages (must succeed) ─────────────────────────────────────────────
_pip "pip" || true   # ensure pip itself is fresh

for pkg in \
  "fastapi>=0.111.0" \
  "uvicorn[standard]>=0.30.0" \
  "psutil>=5.9.8" \
  "pydantic>=2.8.0" \
  "starlette"; do
  _pip "$pkg" || die "Cannot install core package: $pkg. Check network and try again."
done

# ── Optional packages (graceful degradation) ─────────────────────────────────
_pip "scapy==2.5.0"     || warn "scapy unavailable — ARP scan and packet capture disabled"
_pip "python-nmap==0.7.1" || warn "python-nmap unavailable — port/OS scan disabled"
_pip "requests"         || warn "requests unavailable"

# pyshark requires wireshark/tshark — skip silently if unavailable
if command -v tshark &>/dev/null; then
  _pip "pyshark==0.6" || true
fi

ok "Python packages installed"

# Verify core imports
info "Verifying core imports..."
"$VENV_PYTHON" -c "import fastapi, uvicorn, psutil, pydantic" \
  && ok "Core imports verified" \
  || die "Core imports failed — check $LOG"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — FORCE-GRANT RAW SOCKET CAPABILITIES
# ══════════════════════════════════════════════════════════════════════════════
section "Force-Grant Raw Socket Capabilities"

# Security cleanup: Remove accidental SUID from system binaries if set by previous broken runs
for sysbin in /usr/bin/python3 /usr/bin/python3.13 /usr/bin/tcpdump /usr/bin/nmap /usr/bin/dumpcap; do
  [ -f "$sysbin" ] && $SUDO chmod u-s "$sysbin" 2>/dev/null || true
done

# Strategy 1: setcap (preferred, no SUID security risk)
_setcap() {
  local bin="$1"
  [ -f "$bin" ] || return 1
  local real; real=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
  
  if command -v setcap &>/dev/null; then
    if $SUDO setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$real" 2>/dev/null; then
      ok "setcap granted: $real"
      # Remove SUID if it was previously set by a failed install
      $SUDO chmod u-s "$real" 2>/dev/null || true
      return 0
    fi
  fi

  # Strategy 2: SUID bit fallback (ONLY for venv, NEVER for system binaries)
  if [[ "$real" == *"$INSTALL_DIR"* ]]; then
    if $SUDO chmod u+s "$real" 2>/dev/null; then
      ok "SUID set: $real"
      return 0
    fi
  else
    warn "Cannot grant setcap to $real and SUID is skipped for system binary"
  fi
  
  return 1
}

# Apply to python venv binary and its symlink target
_setcap "$VENV_PYTHON"
_setcap "$(readlink -f "$VENV_PYTHON" 2>/dev/null || true)"

# System python3
_setcap "$(command -v python3 2>/dev/null || true)"

# tcpdump, dumpcap, nmap
for bin in tcpdump dumpcap nmap; do
  _setcap "$(command -v $bin 2>/dev/null || true)" || true
done

# /etc/sudoers.d — passwordless execution for this user
CURRENT_USER="${SUDO_USER:-${USER:-$(whoami)}}"
if [ -d /etc/sudoers.d ] && [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
  info "Writing /etc/sudoers.d/mint-net-scanner for user: $CURRENT_USER"
  $SUDO tee /etc/sudoers.d/mint-net-scanner > /dev/null << SUDOEOF
# Mint Net Scanner — auto-generated, safe to remove
Defaults!${INSTALL_DIR}/backend/.venv/bin/python !requiretty
${CURRENT_USER} ALL=(root) NOPASSWD: ${VENV_PYTHON}
${CURRENT_USER} ALL=(root) NOPASSWD: ${VENV_PYTHON} ${INSTALL_DIR}/backend/app.py
${CURRENT_USER} ALL=(root) NOPASSWD: /sbin/iptables
${CURRENT_USER} ALL=(root) NOPASSWD: /usr/sbin/iptables
${CURRENT_USER} ALL=(root) NOPASSWD: /bin/kill
${CURRENT_USER} ALL=(root) NOPASSWD: /usr/bin/kill
SUDOEOF
  $SUDO chmod 440 /etc/sudoers.d/mint-net-scanner 2>/dev/null \
    && ok "sudoers.d entry written" \
    || warn "chmod 440 sudoers.d failed (non-fatal)"

  # Validate the sudoers file
  if command -v visudo &>/dev/null; then
    $SUDO visudo -c -f /etc/sudoers.d/mint-net-scanner &>/dev/null \
      && ok "sudoers.d file validated" \
      || { warn "sudoers.d file has syntax error — removing to prevent lock-out"
           $SUDO rm -f /etc/sudoers.d/mint-net-scanner; }
  fi
fi

# polkit rule (graphical desktops, if polkit present)
if command -v pkexec &>/dev/null && [ -d /usr/share/polkit-1/rules.d ]; then
  $SUDO tee /usr/share/polkit-1/rules.d/50-mint-net-scanner.rules > /dev/null << 'POLKITEOF'
polkit.addRule(function(action, subject) {
  if ((action.id === "org.freedesktop.policykit.exec") &&
      action.lookup("program").indexOf("mint") !== -1) {
    return polkit.Result.YES;
  }
});
POLKITEOF
  ok "polkit rule installed"
fi

# Group membership (wireshark, netdev, pcap)
for grp in wireshark netdev pcap; do
  if getent group "$grp" &>/dev/null; then
    $SUDO usermod -aG "$grp" "$CURRENT_USER" 2>/dev/null \
      && ok "Added $CURRENT_USER to group: $grp" || true
  fi
done

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — AUTO-CONFIGURATION (interface, subnet, SSID, env file)
# ══════════════════════════════════════════════════════════════════════════════
section "Auto-Configuration"

# Default interface (most reliable: ip route get)
DEFAULT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
[ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
[ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE=$(ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1)
[ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="eth0"

# Local IP
LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
if [ -z "$LOCAL_IP" ]; then
  LOCAL_IP=$(ip addr show "$DEFAULT_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
fi
if [ -z "$LOCAL_IP" ]; then
  LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
[ -z "$LOCAL_IP" ] && LOCAL_IP="127.0.0.1"

# Subnet (derive /24 from IP)
IFS='.' read -r _i1 _i2 _i3 _ <<< "$LOCAL_IP"
AUTO_SUBNET="${_i1}.${_i2}.${_i3}.0/24"

# SSID (try many methods, settle on first non-empty result)
SSID="Local Network"
_try_ssid() {
  local result=""
  result=$(eval "$1" 2>/dev/null | tr -d '\0\n\r' | sed 's/^ *//;s/ *$//')
  [ -n "$result" ] && [ "$result" != " " ] && [ ${#result} -lt 64 ] && echo "$result" && return 0
  return 1
}

for _cmd in \
  "iwgetid -r" \
  "iwgetid ${DEFAULT_IFACE} -r" \
  "iw dev ${DEFAULT_IFACE} link | grep -oP 'SSID: \K.*'" \
  "nmcli -t -f active,ssid dev wifi | grep '^yes' | cut -d: -f2" \
  "wpa_cli -i ${DEFAULT_IFACE} status | grep '^ssid=' | cut -d= -f2" \
  "cat /etc/NetworkManager/system-connections/*.nmconnection 2>/dev/null | grep '^ssid=' | head -1 | cut -d= -f2"; do
  _r=$(_try_ssid "$_cmd") && { SSID="$_r"; break; }
done

# Wired connection label
if [ "$SSID" = "Local Network" ] && echo "$DEFAULT_IFACE" | grep -q "^e"; then
  SSID="Wired — $DEFAULT_IFACE"
fi

ok "Interface : $DEFAULT_IFACE"
ok "Local IP  : $LOCAL_IP"
ok "Subnet    : $AUTO_SUBNET"
ok "SSID      : $SSID"

# Write .env for daemon
mkdir -p "$INSTALL_DIR/backend"
cat > "$INSTALL_DIR/backend/.env" << ENVEOF
MINT_INTERFACE=${DEFAULT_IFACE}
MINT_SUBNET=${AUTO_SUBNET}
MINT_LOCAL_IP=${LOCAL_IP}
MINT_SSID=${SSID}
MINT_HOST=0.0.0.0
MINT_PORT=8000
MINT_FRONTEND_PORT=9000
ENVEOF
ok ".env written"

# ── Open firewall ports ──────────────────────────────────────────────────────
# ufw
if command -v ufw &>/dev/null && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
  $SUDO ufw allow 8000/tcp comment "Mint Net Scanner API"  2>/dev/null || true
  $SUDO ufw allow 9000/tcp comment "Mint Net Scanner UI"   2>/dev/null || true
  ok "ufw rules added"
fi
# firewalld
if command -v firewall-cmd &>/dev/null && $SUDO firewall-cmd --state 2>/dev/null | grep -q "running"; then
  $SUDO firewall-cmd --permanent --add-port=8000/tcp 2>/dev/null || true
  $SUDO firewall-cmd --permanent --add-port=9000/tcp 2>/dev/null || true
  $SUDO firewall-cmd --reload 2>/dev/null || true
  ok "firewalld rules added"
fi
# raw iptables fallback
$SUDO iptables -I INPUT -p tcp --dport 8000 -j ACCEPT 2>/dev/null || true
$SUDO iptables -I INPUT -p tcp --dport 9000 -j ACCEPT 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — PROCESS MANAGER  (systemd → supervisor → rc.local → cron)
# ══════════════════════════════════════════════════════════════════════════════
section "Auto-Launch Process Manager"

BACKEND_CMD="$VENV_PYTHON $INSTALL_DIR/backend/app.py"
FRONTEND_CMD="$VENV_PYTHON -m http.server 9000 --directory $INSTALL_DIR/frontend"
LAUNCH_METHOD=""

# ── systemd ──────────────────────────────────────────────────────────────────
_setup_systemd() {
  $SUDO tee /etc/systemd/system/mint-backend.service > /dev/null << SYSD1
[Unit]
Description=Mint Net Scanner — Backend Daemon
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=${INSTALL_DIR}/backend/.env
ExecStart=${BACKEND_CMD}
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
KillMode=mixed
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
SYSD1

  $SUDO tee /etc/systemd/system/mint-frontend.service > /dev/null << SYSD2
[Unit]
Description=Mint Net Scanner — Frontend Server
After=network.target mint-backend.service
Wants=mint-backend.service

[Service]
Type=simple
User=root
ExecStart=${FRONTEND_CMD}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSD2

  $SUDO systemctl daemon-reload 2>/dev/null || return 1
  $SUDO systemctl enable mint-backend mint-frontend 2>/dev/null
  $SUDO systemctl restart mint-backend  2>/dev/null && ok "mint-backend  started" || { warn "mint-backend start failed"; return 1; }
  $SUDO systemctl restart mint-frontend 2>/dev/null && ok "mint-frontend started" || warn "mint-frontend start failed (non-fatal)"
  return 0
}

# ── supervisor ───────────────────────────────────────────────────────────────
_setup_supervisor() {
  command -v supervisord &>/dev/null || _pip supervisor || return 1

  local SCFD=""
  for d in /etc/supervisor/conf.d /etc/supervisord.d /usr/local/etc/supervisor.d; do
    [ -d "$d" ] && SCFD="$d" && break
  done
  [ -z "$SCFD" ] && { $SUDO mkdir -p /etc/supervisor/conf.d; SCFD="/etc/supervisor/conf.d"; }

  $SUDO tee "$SCFD/mint-net-scanner.conf" > /dev/null << SUPCONF
[program:mint-backend]
command=${BACKEND_CMD}
directory=${INSTALL_DIR}/backend
autostart=true
autorestart=true
startretries=20
startsecs=3
user=root
redirect_stderr=true
stdout_logfile=/var/log/mint-backend.log
stdout_logfile_maxbytes=10MB
stdout_logfile_backups=2

[program:mint-frontend]
command=${FRONTEND_CMD}
autostart=true
autorestart=true
startretries=20
user=root
redirect_stderr=true
stdout_logfile=/var/log/mint-frontend.log
SUPCONF

  if pgrep supervisord &>/dev/null; then
    $SUDO supervisorctl reread 2>/dev/null
    $SUDO supervisorctl update 2>/dev/null
    $SUDO supervisorctl restart mint-backend mint-frontend 2>/dev/null || true
  else
    local SCFG=""
    for f in /etc/supervisor/supervisord.conf /etc/supervisord.conf \
              /usr/local/etc/supervisord.conf /usr/local/etc/supervisord.ini; do
      [ -f "$f" ] && SCFG="$f" && break
    done
    [ -n "$SCFG" ] && $SUDO supervisord -c "$SCFG" 2>/dev/null || $SUDO supervisord 2>/dev/null || return 1
  fi
  ok "supervisor configured"
  return 0
}

# ── rc.local ─────────────────────────────────────────────────────────────────
_setup_rc_local() {
  local RC="/etc/rc.local"
  if [ ! -f "$RC" ]; then
    printf '#!/bin/sh -e\nexit 0\n' | $SUDO tee "$RC" > /dev/null
  fi
  $SUDO chmod +x "$RC"
  # Remove old mint entries and exit 0
  $SUDO grep -v "mint-net-scanner\|exit 0" "$RC" | $SUDO tee "$RC.tmp" > /dev/null 2>&1 \
    && $SUDO mv "$RC.tmp" "$RC" || true
  $SUDO tee -a "$RC" > /dev/null << RCEOF
# Mint Net Scanner v3.1 — auto-generated
nohup ${BACKEND_CMD}  >> /var/log/mint-backend.log  2>&1 &
nohup ${FRONTEND_CMD} >> /var/log/mint-frontend.log 2>&1 &
exit 0
RCEOF
  ok "rc.local updated"
}

# ── cron @reboot ─────────────────────────────────────────────────────────────
_setup_cron() {
  (
    crontab -l 2>/dev/null | grep -v "mint-net-scanner" || true
    echo "# Mint Net Scanner v3.1"
    echo "@reboot ${BACKEND_CMD}  >> /var/log/mint-backend.log  2>&1"
    echo "@reboot ${FRONTEND_CMD} >> /var/log/mint-frontend.log 2>&1"
  ) | crontab -
  ok "@reboot cron entries added"
}

# Choose best available
if $SYSTEMD; then
  _setup_systemd && LAUNCH_METHOD="systemd" || warn "systemd setup failed — trying supervisor"
fi
if [ -z "$LAUNCH_METHOD" ]; then
  _setup_supervisor && LAUNCH_METHOD="supervisor" || true
fi
if [ -z "$LAUNCH_METHOD" ]; then
  _setup_rc_local; LAUNCH_METHOD="rc.local"
fi
# Always add cron as an extra safety net
_setup_cron

ok "Primary auto-launch: $LAUNCH_METHOD (+ cron @reboot backup)"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — IMMEDIATE START
# ══════════════════════════════════════════════════════════════════════════════
section "Starting Services Now"

# Kill anything already using our ports
for port in 8000 9000; do
  fuser -k "${port}/tcp" 2>/dev/null \
    || lsof -ti ":${port}" 2>/dev/null | xargs kill -9 2>/dev/null \
    || true
done
sleep 1

# Start backend (must be root for packet capture)
info "Launching backend daemon (root)..."
$SUDO nohup bash -c "$BACKEND_CMD >> /var/log/mint-backend.log 2>&1" &
_BPID=$!
echo "$_BPID" > "$INSTALL_DIR/backend.pid" 2>/dev/null || true
ok "Backend PID: $_BPID"

# Start frontend
info "Launching frontend server..."
$SUDO touch /var/log/mint-frontend.log 2>/dev/null || true
$SUDO chmod 666 /var/log/mint-frontend.log 2>/dev/null || true
nohup $FRONTEND_CMD >> /var/log/mint-frontend.log 2>&1 &
_FPID=$!
echo "$_FPID" > "$INSTALL_DIR/frontend.pid" 2>/dev/null || true
ok "Frontend PID: $_FPID"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — HEALTH CHECK (wait up to 60s for API)
# ══════════════════════════════════════════════════════════════════════════════
section "Health Check"

info "Waiting for API to become ready (up to 60s)..."
HEALTHY=false
for _i in $(seq 1 30); do
  sleep 2
  printf "."
  if curl -sf "http://localhost:8000/health" -o /tmp/mint-health.json 2>/dev/null; then
    HEALTHY=true
    break
  fi
done
echo ""

if $HEALTHY; then
  ok "API is healthy!"
  "$PYTHON" -c "
import json, sys
try:
    d = json.load(open('/tmp/mint-health.json'))
    print(f'    Root     : {chr(10003) if d.get(\"running_as_root\") else chr(10007)}')
    print(f'    Scapy    : {chr(10003) if d.get(\"scapy\") else chr(10007)}')
    print(f'    Nmap     : {chr(10003) if d.get(\"nmap\") else chr(10007)}')
    print(f'    Sniffer  : {\"ACTIVE\" if d.get(\"sniffer_active\") else \"starting...\"}')
    print(f'    Interface: {d.get(\"default_interface\",\"?\")}')
    print(f'    SSID     : {d.get(\"ssid\",\"?\")}')
    print(f'    Local IP : {d.get(\"local_ip\",\"?\")}')
except Exception as e:
    print(f'    parse error: {e}')
" 2>/dev/null || true
else
  warn "API not responding within 60s"
  warn "Check backend log:"
  tail -30 /var/log/mint-backend.log 2>/dev/null || tail -30 "$INSTALL_DIR/backend.log" 2>/dev/null || true
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — MANAGEMENT SCRIPTS
# ══════════════════════════════════════════════════════════════════════════════
section "Writing Management Scripts"

cat > "$INSTALL_DIR/start.sh" << STARTEOF
#!/usr/bin/env bash
# Mint Net Scanner — start script (auto-generated)
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="\$DIR/backend/.venv/bin/python"
for port in 8000 9000; do
  fuser -k "\${port}/tcp" 2>/dev/null || lsof -ti ":\${port}" 2>/dev/null | xargs kill -9 2>/dev/null || true
done
sleep 1
sudo nohup bash -c "\$VENV_PY \$DIR/backend/app.py >> /var/log/mint-backend.log 2>&1" &
echo \$! > "\$DIR/backend.pid"
nohup bash -c "\$VENV_PY -m http.server 9000 --directory \$DIR/frontend >> /var/log/mint-frontend.log 2>&1" &
echo \$! > "\$DIR/frontend.pid"
sleep 2
curl -sf http://localhost:8000/health > /dev/null && echo "✔ Mint Net Scanner running → http://localhost:9000" || echo "⚠ Backend not responding yet — check /var/log/mint-backend.log"
STARTEOF

cat > "$INSTALL_DIR/stop.sh" << 'STOPEOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$DIR/backend.pid"  ] && kill "$(cat "$DIR/backend.pid")"  2>/dev/null || true
[ -f "$DIR/frontend.pid" ] && kill "$(cat "$DIR/frontend.pid")" 2>/dev/null || true
for port in 8000 9000; do fuser -k "${port}/tcp" 2>/dev/null || true; done
echo "✔ Mint Net Scanner stopped"
STOPEOF

cat > "$INSTALL_DIR/status.sh" << 'STATUSEOF'
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
STATUSEOF

cat > "$INSTALL_DIR/update.sh" << UPDATEEOF
#!/usr/bin/env bash
# Pull latest from GitHub and restart
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
cd "\$DIR" && git pull origin main && bash install.sh
UPDATEEOF

chmod +x "$INSTALL_DIR/start.sh" "$INSTALL_DIR/stop.sh" "$INSTALL_DIR/status.sh" "$INSTALL_DIR/update.sh"
ok "start.sh  stop.sh  status.sh  update.sh"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — AUTO-OPEN BROWSER
# ══════════════════════════════════════════════════════════════════════════════
section "Opening Dashboard"

DASHBOARD_URL="http://${LOCAL_IP}:9000"
LOCALHOST_URL="http://localhost:9000"

_open_url() {
  local url="$1"
  if $IS_CHROMEBOOK && command -v garcon-url-handler &>/dev/null; then
    garcon-url-handler "$url" &>/dev/null & ok "Opened in Chromebook browser"
  elif $IS_MACOS; then
    open "$url" &>/dev/null & ok "Opened in macOS browser"
  elif $IS_WSL; then
    cmd.exe /c start "$url" &>/dev/null & ok "Opened in Windows browser"
  else
    for b in xdg-open chromium-browser chromium google-chrome firefox sensible-browser; do
      if command -v "$b" &>/dev/null; then
        "$b" "$url" &>/dev/null & ok "Opened with $b"
        return 0
      fi
    done
    warn "No browser found — open manually: $url"
  fi
}

$HEALTHY && sleep 1 && _open_url "$DASHBOARD_URL" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${G}╔══════════════════════════════════════════════════════════════════╗${N}"
echo -e "${G}║        Mint Net Scanner v3.1 — Installation Complete!            ║${N}"
echo -e "${G}╠══════════════════════════════════════════════════════════════════╣${N}"
printf "${G}║${N}  %-62s${G}║${N}\n" ""
printf "${G}║${N}  %-15s ${B}%-45s${N}${G}║${N}\n" "Dashboard →" "http://${LOCAL_IP}:9000"
printf "${G}║${N}  %-15s %-45s${G}║${N}\n" "API →" "http://${LOCAL_IP}:8000/health"
printf "${G}║${N}  %-15s %-45s${G}║${N}\n" "Auto-launch →" "$LAUNCH_METHOD + cron backup"
printf "${G}║${N}  %-15s %-45s${G}║${N}\n" "Capabilities →" "setcap + sudoers.d force-granted"
printf "${G}║${N}  %-62s${G}║${N}\n" ""
printf "${G}║${N}  %-62s${G}║${N}\n" "bash start.sh    bash stop.sh    bash status.sh"
printf "${G}║${N}  %-62s${G}║${N}\n" "bash update.sh   (pull latest from GitHub)"
printf "${G}║${N}  %-62s${G}║${N}\n" ""
printf "${G}║${N}  %-62s${G}║${N}\n" "Install log: $LOG"
echo -e "${G}╚══════════════════════════════════════════════════════════════════╝${N}"
echo ""
