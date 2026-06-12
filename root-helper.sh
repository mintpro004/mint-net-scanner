#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  MINT NET SCANNER — Root Access & Capability Helper
# ══════════════════════════════════════════════════════════════════════════════

C='\033[0;36m' G='\033[0;32m' Y='\033[1;33m' R='\033[0;31m' N='\033[0m' B='\033[1m'

echo -e "\n${B}━━  Root Access & Capability Helper  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"

# 1. Check current user
echo -n "Current User: "
whoami
if [ "$EUID" -eq 0 ]; then
    echo -e "${G}✔ Running as root${N}"
else
    echo -e "${Y}⚠ Running as non-root user${N}"
fi

# 2. Check sudoers.d
echo -e "\n${B}[1] Checking sudoers.d configuration...${N}"
if [ -f /etc/sudoers.d/mint-net-scanner ]; then
    echo -e "${G}✔ /etc/sudoers.d/mint-net-scanner exists${N}"
    ls -l /etc/sudoers.d/mint-net-scanner
else
    echo -e "${R}✘ sudoers.d entry missing${N}"
    echo "To fix, run: bash install.sh"
fi

# 3. Check capabilities
echo -e "\n${B}[2] Checking binary capabilities (raw socket access)...${N}"
VENV_PYTHON="./backend/.venv/bin/python3"
if [ -f "$VENV_PYTHON" ]; then
    REAL_PY=$(readlink -f "$VENV_PYTHON")
    echo "Python Binary: $REAL_PY"
    if command -v getcap &>/dev/null; then
        CAPS=$(getcap "$REAL_PY")
        if [[ "$CAPS" == *"cap_net_raw"* ]]; then
            echo -e "${G}✔ cap_net_raw granted${N}"
        else
            echo -e "${R}✘ cap_net_raw MISSING${N}"
            echo "To fix: sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $REAL_PY"
        fi
    else
        echo -e "${Y}⚠ 'getcap' not found, cannot verify capabilities automatically${N}"
    fi
else
    echo -e "${R}✘ Virtualenv python not found at $VENV_PYTHON${N}"
fi

# 4. Check Nmap
echo -e "\n${B}[3] Checking Nmap permissions...${N}"
if command -v nmap &>/dev/null; then
    NMAP_PATH=$(which nmap)
    if [ -u "$NMAP_PATH" ]; then
        echo -e "${Y}⚠ Nmap has SUID bit set${N}"
    fi
    # Test if nmap can run OS detection
    if sudo -n nmap -O 127.0.0.1 &>/dev/null; then
        echo -e "${G}✔ sudo nmap -O works (passwordless)${N}"
    else
        echo -e "${R}✘ sudo nmap -O failed or requires password${N}"
    fi
else
    echo -e "${R}✘ nmap not installed${N}"
fi

echo -e "\n${B}━━  How to grant full access  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo -e "1. ${C}Always use the start script:${N}  bash start.sh"
echo -e "   This script uses 'sudo' for the backend automatically."
echo ""
echo -e "2. ${C}Manual start (Recommended):${N}"
echo -e "   cd backend"
echo -e "   sudo ../backend/.venv/bin/python3 app.py"
echo ""
echo -e "3. ${C}If you see 'Permission Denied':${N}"
echo -e "   The installer already force-granted capabilities. If they were lost:"
echo -e "   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip \$(readlink -f backend/.venv/bin/python3)"
echo ""
echo -e "${B}Note:${N} OS detection and ARP scanning ${B}REQUIRE${N} root/sudo privileges."
echo -e "The dashboard will show 'Unknown OS' if run without proper access."
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
