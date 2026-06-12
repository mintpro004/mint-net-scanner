"""
Mint Net Scanner v3.1 — Production Backend Daemon
Hardened: graceful degradation on every import, full error handling,
SSID detection, full device details, investigate, traffic analysis.
Run: sudo python app.py   (root needed for ARP + packet capture)
"""

import asyncio
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List, Optional

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(os.path.dirname(__file__), "..", "backend.log"),
            mode="a", encoding="utf-8"
        ),
    ]
)
log = logging.getLogger("mint")

# ── Optional heavy imports (graceful degradation) ────────────────────────────
SCAPY_OK = False
NMAP_OK  = False

try:
    import scapy.all as scapy
    SCAPY_OK = True
    log.info("scapy loaded OK")
except Exception as e:
    log.warning(f"scapy unavailable ({e}) — ARP scan and packet capture disabled")

try:
    import nmap as _nmap
    # Quick sanity check
    _nmap.PortScanner()
    NMAP_OK = True
    log.info("python-nmap loaded OK")
except Exception as e:
    log.warning(f"python-nmap unavailable ({e}) — port/OS scan disabled")

# ── Core imports (must succeed — installer guarantees these) ─────────────────
try:
    import psutil
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
except ImportError as e:
    log.critical(f"Core package missing: {e}")
    log.critical("Run installer again: bash install.sh")
    sys.exit(1)

# ── Load .env config ──────────────────────────────────────────────────────────
def _load_env() -> None:
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())
_load_env()

HOST       = os.environ.get("MINT_HOST", "0.0.0.0")
PORT       = int(os.environ.get("MINT_PORT", "8000"))
DEF_IFACE  = os.environ.get("MINT_INTERFACE", "")
DEF_SUBNET = os.environ.get("MINT_SUBNET", "")
ENV_SSID   = os.environ.get("MINT_SSID", "")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="Mint Net Scanner", version="3.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global live state ─────────────────────────────────────────────────────────
_packets:       deque = deque(maxlen=500)
_alerts:        deque = deque(maxlen=300)
_devices:       Dict[str, dict] = {}
_traffic_hist:  deque = deque(maxlen=120)  # 1-second snapshots
_proto_counts:  Dict[str, int] = defaultdict(int)
_ip_flows:      Dict[str, dict] = defaultdict(lambda: {
    "tx": 0, "rx": 0, "packets": 0, "ports": set(), "last_seen": ""
})
_bps   = 0
_pps   = 0
_total = 0
_sniffing = False
_sniff_thread: Optional[threading.Thread] = None

# ── Utility: safe subprocess ──────────────────────────────────────────────────
def _run(cmd: list, timeout: int = 5) -> str:
    """Run a command, return stdout string, never raise."""
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout, text=True
        )
    except Exception:
        return ""

# ── Network helpers ───────────────────────────────────────────────────────────
def default_interface() -> str:
    if DEF_IFACE:
        return DEF_IFACE
    out = _run(["ip", "route", "get", "8.8.8.8"])
    m = re.search(r"dev\s+(\S+)", out)
    if m:
        return m.group(1)
    # Fallback: first up non-loopback interface
    try:
        for name, stats in psutil.net_if_stats().items():
            if name != "lo" and stats.isup:
                return name
    except Exception:
        pass
    return "eth0"


def local_ip() -> str:
    out = _run(["ip", "route", "get", "8.8.8.8"])
    m = re.search(r"src\s+([\d.]+)", out)
    if m:
        return m.group(1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def local_subnet() -> str:
    if DEF_SUBNET:
        return DEF_SUBNET
    ip = local_ip()
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"


def get_ssid() -> str:
    """Detect current WiFi SSID using multiple methods."""
    if ENV_SSID and ENV_SSID not in ("", "Unknown Network", "Local Network"):
        return ENV_SSID

    iface = default_interface()

    def _try(cmd: list) -> str:
        out = _run(cmd, timeout=3).strip()
        return out if out and len(out) < 64 else ""

    # iwgetid
    s = _try(["iwgetid", "-r"])
    if s:
        return s
    s = _try(["iwgetid", iface, "-r"])
    if s:
        return s

    # iw dev link
    out = _run(["iw", "dev", iface, "link"], timeout=3)
    m = re.search(r"SSID:\s*(.+)", out)
    if m:
        return m.group(1).strip()

    # nmcli
    out = _run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], timeout=3)
    for line in out.splitlines():
        if line.startswith("yes:"):
            return line.split(":", 1)[1].strip()

    # wpa_cli
    out = _run(["wpa_cli", "-i", iface, "status"], timeout=3)
    m = re.search(r"(?i)^ssid=(.+)", out, re.MULTILINE)
    if m:
        return m.group(1).strip()

    # Wired
    st = psutil.net_if_stats().get(iface)
    if st and iface.startswith("e"):
        return f"Wired — {iface}"

    return "Local Network"


def get_network_details() -> dict:
    """Full network connection details."""
    iface  = default_interface()
    ip     = local_ip()
    addrs  = psutil.net_if_addrs().get(iface, [])
    stats  = psutil.net_if_stats().get(iface)

    ipv4_info = next((a for a in addrs if a.family == socket.AF_INET), None)
    ipv6_info = next((a for a in addrs if a.family == socket.AF_INET6), None)
    mac_info  = next((a for a in addrs if a.family == psutil.AF_LINK), None)

    # Gateway
    gateway = ""
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via ([\d.]+)", out)
    if m:
        gateway = m.group(1)

    # DNS servers
    dns_servers: List[str] = []
    for fpath in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"]:
        if os.path.exists(fpath):
            with open(fpath) as fh:
                for line in fh:
                    m2 = re.match(r"nameserver\s+([\d.a-f:]+)", line)
                    if m2:
                        dns_servers.append(m2.group(1))
            break

    # WiFi signal
    signal_dbm = None
    out = _run(["iw", "dev", iface, "station", "dump"])
    m = re.search(r"signal:\s+([-\d]+)", out)
    if m:
        try:
            signal_dbm = int(m.group(1))
        except ValueError:
            pass

    return {
        "ssid":       get_ssid(),
        "interface":  iface,
        "ipv4":       ipv4_info.address if ipv4_info else ip,
        "netmask":    ipv4_info.netmask if ipv4_info else "",
        "ipv6":       ipv6_info.address if ipv6_info else "",
        "mac":        mac_info.address.upper() if mac_info else "",
        "gateway":    gateway,
        "dns":        dns_servers[:4],
        "subnet":     local_subnet(),
        "link_speed": stats.speed if stats else 0,
        "signal_dbm": signal_dbm,
        "is_up":      stats.isup if stats else False,
        "mtu":        stats.mtu if stats else 1500,
        "type":       ("WiFi" if iface.startswith("w")
                       else "Ethernet" if iface.startswith("e")
                       else "Unknown"),
    }

# ── Host enrichment ───────────────────────────────────────────────────────────
def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _mac_vendor(mac: str) -> str:
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    for oui_path in [
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/nmap/nmap-mac-prefixes",
        "/var/lib/ieee-data/oui.txt",
    ]:
        if os.path.exists(oui_path):
            out = _run(["grep", "-im", "1", prefix, oui_path], timeout=2)
            if out:
                parts = out.split("\t")
                return parts[-1].strip() if len(parts) > 1 else out.strip()
    return "Unknown Vendor"


def _scan_ports(ip: str) -> List[int]:
    if not NMAP_OK:
        return []
    try:
        nm = _nmap.PortScanner()
        nm.scan(
            ip,
            ports="21,22,23,25,53,80,110,143,443,445,554,1883,3389,5900,8000,8080,8443,2049,5000,9100",
            arguments="-T4 --open --max-retries 1",
            timeout=30,
        )
        if ip in nm.all_hosts():
            ports: List[int] = []
            for proto in nm[ip].all_protocols():
                ports.extend(
                    p for p in nm[ip][proto]
                    if nm[ip][proto][p]["state"] == "open"
                )
            return sorted(ports)
    except Exception as e:
        log.debug(f"Port scan {ip}: {e}")
    return []


PORT_SERVICES: Dict[int, str] = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    554:"RTSP", 1883:"MQTT", 3389:"RDP", 5900:"VNC",
    8000:"HTTP-Alt", 8080:"HTTP-Proxy", 8443:"HTTPS-Alt",
    2049:"NFS", 5000:"UPnP", 9100:"Print",
}


def _service_versions(ip: str, ports: List[int]) -> dict:
    if not NMAP_OK or not ports:
        return {}
    try:
        nm = _nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports[:12])
        nm.scan(ip, ports=port_str, arguments="-sV --version-light -T4 --max-retries 1", timeout=30)
        services = {}
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for p in nm[ip][proto]:
                    info = nm[ip][proto][p]
                    services[p] = {
                        "name":    info.get("name", ""),
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                        "extra":   info.get("extrainfo", ""),
                    }
        return services
    except Exception:
        return {}


def _fingerprint_os(ip: str) -> str:
    if not NMAP_OK:
        return "Unknown OS"
    try:
        nm = _nmap.PortScanner()
        nm.scan(ip, arguments="-O --osscan-guess -T4 --max-retries 1", timeout=20)
        if ip in nm.all_hosts():
            osm = nm[ip].get("osmatch", [])
            if osm:
                return f"{osm[0].get('name','?')} ({osm[0].get('accuracy','?')}%)"
    except Exception:
        pass
    return "Unknown OS"


def _risk_score(ports: List[int], vendor: str, os_name: str) -> int:
    score = 0
    risky = {23:40, 21:30, 3389:30, 5900:25, 554:20, 8000:10,
             80:5, 8080:8, 445:25, 1883:15}
    for p in ports:
        score += risky.get(p, 0)
    if any(v in vendor.lower() for v in ["hikvision", "dahua", "tp-link", "shenzhen"]):
        score += 20
    if any(v in os_name.lower() for v in ["windows xp", "windows 7", "windows 2003"]):
        score += 25
    return min(score, 100)


def _classify(ports: List[int], hostname: str, vendor: str, os_name: str) -> str:
    h, v, o = hostname.lower(), vendor.lower(), os_name.lower()
    if any(p in ports for p in [554, 8000]) or "cam" in h or "dvr" in h:
        return "IoT / Camera"
    if any(p in ports for p in [2049, 5000]) or "synology" in v or "qnap" in v:
        return "NAS / Storage"
    if 53 in ports or 67 in ports or any(k in h for k in ["router", "gateway"]):
        return "Router / Gateway"
    if 3389 in ports or (5900 in ports and "windows" in o):
        return "Windows Workstation"
    if 22 in ports and "linux" in o:
        return "Linux Server"
    if 445 in ports and "windows" in o:
        return "Windows Server"
    if 1883 in ports:
        return "IoT / MQTT"
    if 9100 in ports:
        return "Network Printer"
    if "android" in o or "iphone" in o:
        return "Mobile Device"
    if "raspberry" in v or "raspberry" in h:
        return "Raspberry Pi"
    return "Endpoint"


def enrich_host(ip: str, mac: str) -> dict:
    hostname = _resolve_hostname(ip)
    vendor   = _mac_vendor(mac)
    ports    = _scan_ports(ip)
    os_name  = _fingerprint_os(ip)
    svc_vers = _service_versions(ip, ports)
    rscore   = _risk_score(ports, vendor, os_name)
    category = _classify(ports, hostname, vendor, os_name)

    # Firewall status
    fw = "Allowed"
    try:
        r = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=2
        )
        if r.returncode == 0:
            fw = "Blocked"
    except Exception:
        pass

    # Active connections
    conns = []
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.raddr and c.raddr.ip == ip and c.status == "ESTABLISHED":
                conns.append({
                    "local":  f"{c.laddr.ip}:{c.laddr.port}",
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    "status": c.status,
                    "pid":    c.pid,
                })
    except Exception:
        pass

    flow = _ip_flows.get(ip, {})

    return {
        "id": ip, "ip": ip,
        "mac": mac.upper() if mac else "00:00:00:00:00:00",
        "hostname": hostname,
        "vendor": vendor,
        "os": os_name,
        "status": "online",
        "dpiCategory": category,
        "activeConnections": len(conns),
        "connectionDetails": conns[:5],
        "txBytes": flow.get("tx", 0),
        "rxBytes": flow.get("rx", 0),
        "packetCount": flow.get("packets", 0),
        "riskScore": rscore,
        "ports": ports,
        "portServices": {p: PORT_SERVICES.get(p, "Unknown") for p in ports},
        "serviceVersions": svc_vers,
        "firewallStatus": fw,
        "lastSeen": datetime.now().isoformat(),
        "firstSeen": datetime.now().isoformat(),
    }


def _generate_ids(device: dict) -> None:
    ip    = device["ip"]
    ports = device.get("ports", [])
    svcs  = device.get("portServices", {})

    def _add(aid: str, sev: str, ttype: str, desc: str) -> None:
        if not any(a["id"] == aid for a in _alerts):
            _alerts.append({
                "id": aid, "severity": sev, "threat_type": ttype,
                "description": desc, "source_ip": ip, "destination_ip": "Any",
                "timestamp": datetime.now().isoformat(),
            })

    risky_ports = [p for p in ports if p in [23, 21, 3389, 5900, 554, 8000, 445, 1883]]
    if risky_ports:
        svc_list = ", ".join(f"{p}/{svcs.get(p,'?')}" for p in risky_ports)
        _add(f"ids_{ip}_ports",
             "CRITICAL" if len(risky_ports) >= 3 else "HIGH",
             "Dangerous Open Ports",
             f"{ip} ({device['hostname']}) has {len(risky_ports)} high-risk port(s): {svc_list}")

    if device.get("dpiCategory") == "IoT / Camera":
        _add(f"ids_{ip}_iot", "HIGH", "Unsecured IoT Device",
             f"Camera/IoT {ip} ({device['vendor']}) — verify credentials and firmware")

    if 23 in ports:
        _add(f"ids_{ip}_telnet", "CRITICAL", "Telnet Enabled",
             f"{ip} has Telnet (port 23) — unencrypted remote access, disable immediately")

    if 445 in ports:
        _add(f"ids_{ip}_smb", "HIGH", "SMB Exposed",
             f"{ip} has SMB (port 445) — potential ransomware/lateral movement vector")

    if device.get("riskScore", 0) >= 65:
        _add(f"ids_{ip}_highrisk", "CRITICAL", "High Risk Host",
             f"{ip} risk score {device['riskScore']}/100 — immediate review recommended")

# ── Live packet sniffer ───────────────────────────────────────────────────────
def _pkt_callback(pkt: Any) -> None:
    global _bps, _pps, _total
    _total += 1
    size = len(pkt)
    _bps = int(_bps * 0.85 + size * 8 * 0.15)
    _pps = max(1, int(_pps * 0.85 + 1 * 0.15))

    src = dst = proto = "?"
    sport = dport = 0
    info_str = ""

    try:
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            _ip_flows[src]["tx"]      += size
            _ip_flows[dst]["rx"]      += size
            _ip_flows[src]["packets"] += 1
            _ip_flows[src]["last_seen"] = datetime.now().isoformat()

        if pkt.haslayer("TCP"):
            sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
            proto = "TCP"
            _ip_flows[src]["ports"].add(dport)
            if dport == 443:
                info_str = "HTTPS"
            elif dport == 80:
                info_str = "HTTP"
            elif dport == 53:
                info_str = "DNS"
        elif pkt.haslayer("UDP"):
            sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
            proto = "UDP"
            if dport == 53:
                info_str = "DNS"
            elif dport == 67:
                info_str = "DHCP"
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"
            info_str = "Ping/ICMP"
        elif pkt.haslayer("ARP"):
            proto = "ARP"
            try:
                src = pkt["ARP"].psrc or src
                dst = pkt["ARP"].pdst or dst
                info_str = "ARP"
            except Exception:
                pass

    except Exception:
        pass

    _proto_counts[proto] += 1

    _packets.append({
        "id":          f"p{_total}",
        "timestamp":   datetime.now().strftime("%H:%M:%S"),
        "protocol":    proto,
        "src_ip":      src,
        "dst_ip":      dst,
        "sport":       sport,
        "dport":       dport,
        "packet_size": size,
        "info":        info_str or f"Frame #{_total}",
    })

    # IDS: port scan detection
    try:
        recent = [p for p in list(_packets)[-50:] if p.get("src_ip") == src]
        unique_dports = {p["dport"] for p in recent if p.get("dport")}
        if len(unique_dports) > 15:
            aid = f"ids_portscan_{src}"
            if not any(a["id"] == aid for a in _alerts):
                _alerts.append({
                    "id": aid, "severity": "HIGH", "threat_type": "Port Scan",
                    "description": f"{src} probed {len(unique_dports)} distinct ports in <50 packets.",
                    "source_ip": src, "destination_ip": "*",
                    "timestamp": datetime.now().isoformat(),
                })
    except Exception:
        pass


def _traffic_sampler_loop() -> None:
    """Background thread: captures 1-second traffic snapshots."""
    while True:
        try:
            time.sleep(1)
            net = psutil.net_io_counters()
            _traffic_hist.append({
                "ts":          datetime.now().isoformat(),
                "bps":         _bps,
                "pps":         _pps,
                "bytes_sent":  net.bytes_sent,
                "bytes_recv":  net.bytes_recv,
                "proto_counts": dict(_proto_counts),
            })
        except Exception:
            pass


def _sniff_loop(iface: str) -> None:
    global _sniffing
    _sniffing = True
    log.info(f"Packet capture started on interface: {iface}")
    try:
        scapy.sniff(
            iface=iface,
            prn=_pkt_callback,
            store=False,
            stop_filter=lambda _: not _sniffing,
        )
    except Exception as e:
        log.error(f"Sniffer error: {e}")
    finally:
        _sniffing = False
        log.info("Packet capture stopped")


def start_sniffer(iface: str) -> None:
    global _sniff_thread
    if not SCAPY_OK:
        log.warning("scapy not available — packet capture disabled")
        return
    if _sniffing:
        return
    _sniff_thread = threading.Thread(
        target=_sniff_loop, args=(iface,), daemon=True, name="mint-sniffer"
    )
    _sniff_thread.start()


def stop_sniffer() -> None:
    global _sniffing
    _sniffing = False

# ── Startup / shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup() -> None:
    iface = default_interface()
    is_root = os.geteuid() == 0
    log.info(
        f"Mint Net Scanner v3.1 | iface={iface} | "
        f"root={is_root} | scapy={SCAPY_OK} | nmap={NMAP_OK}"
    )
    # Background traffic sampler (always runs)
    threading.Thread(
        target=_traffic_sampler_loop, daemon=True, name="mint-traffic-sampler"
    ).start()
    # Start sniffer if we have the required capabilities
    if SCAPY_OK and is_root:
        start_sniffer(iface)
    else:
        if not is_root:
            log.warning(
                "Not running as root — packet capture disabled. "
                "Installer should have set up sudoers.d. "
                "Manual fix: sudo python app.py"
            )
        elif not SCAPY_OK:
            log.warning("scapy not installed — packet capture disabled")

# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    net = get_network_details()
    return {
        "status": "ok",
        "version": "3.1.0",
        "scapy": SCAPY_OK,
        "nmap": NMAP_OK,
        "running_as_root": os.geteuid() == 0,
        "sniffer_active": _sniffing,
        "default_interface": default_interface(),
        "local_subnet": local_subnet(),
        "local_ip": local_ip(),
        "ssid": net["ssid"],
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/v1/metrics")
async def metrics() -> dict:
    net = psutil.net_io_counters()
    ram = psutil.virtual_memory()

    # Refresh device state
    devs = list(_devices.values())
    for d in devs:
        try:
            d["activeConnections"] = sum(
                1 for c in psutil.net_connections(kind="tcp")
                if c.raddr and c.raddr.ip == d["ip"] and c.status == "ESTABLISHED"
            )
        except Exception:
            pass
        d["lastSeen"] = datetime.now().isoformat()
        flow = _ip_flows.get(d["ip"], {})
        d["txBytes"] = flow.get("tx", d.get("txBytes", 0))
        d["rxBytes"]  = flow.get("rx", d.get("rxBytes", 0))

    return {
        "cpu_percent":        round(psutil.cpu_percent(interval=0.1), 1),
        "ram_percent":        round(ram.percent, 1),
        "ram_used_gb":        round(ram.used / 1e9, 2),
        "ram_total_gb":       round(ram.total / 1e9, 2),
        "current_bps":        _bps,
        "current_pps":        _pps,
        "total_packet_count": _total,
        "bytes_sent":         net.bytes_sent,
        "bytes_recv":         net.bytes_recv,
        "active_devices":     devs,
        "active_threats":     list(_alerts),
        "live_packet_flows":  list(_packets)[-50:],
        "proto_counts":       dict(_proto_counts),
        "sniffer_active":     _sniffing,
        "scapy_available":    SCAPY_OK,
        "nmap_available":     NMAP_OK,
        "running_as_root":    os.geteuid() == 0,
        "timestamp":          datetime.now().isoformat(),
    }


@app.get("/api/v1/network")
def network_info() -> dict:
    return get_network_details()


@app.get("/api/v1/traffic/analysis")
def traffic_analysis() -> dict:
    samples = list(_traffic_hist)

    # Top talkers
    top_tx = sorted(_ip_flows.items(), key=lambda x: x[1].get("tx", 0), reverse=True)[:10]
    top_rx = sorted(_ip_flows.items(), key=lambda x: x[1].get("rx", 0), reverse=True)[:10]

    # Protocol breakdown
    total_pkts = max(sum(_proto_counts.values()), 1)
    proto_pct = {
        k: round(v / total_pkts * 100, 1)
        for k, v in sorted(_proto_counts.items(), key=lambda x: -x[1])
    }

    # BPS history
    bps_history = [
        {"ts": s["ts"][-8:], "bps": s["bps"], "pps": s["pps"]}
        for s in samples[-60:]
    ]

    # Anomaly detection
    anomalies = []
    if len(samples) >= 10:
        avg_pps = sum(s["pps"] for s in samples[-10:]) / 10
        if avg_pps > 1000:
            anomalies.append({
                "type": "High PPS",
                "detail": f"Average {avg_pps:.0f} pps (last 10s)",
                "severity": "HIGH",
            })

    # Top conversations
    convos: Dict[str, int] = defaultdict(int)
    for p in list(_packets)[-200:]:
        if p["src_ip"] != "?" and p["dst_ip"] != "?":
            convos[f"{p['src_ip']} → {p['dst_ip']}"] += p["packet_size"]
    top_convos = sorted(convos.items(), key=lambda x: -x[1])[:10]

    return {
        "top_talkers_tx":     [{"ip": ip, "bytes": d.get("tx", 0), "packets": d.get("packets", 0)} for ip, d in top_tx],
        "top_talkers_rx":     [{"ip": ip, "bytes": d.get("rx", 0)} for ip, d in top_rx],
        "protocol_breakdown": proto_pct,
        "bps_history":        bps_history,
        "top_conversations":  [{"pair": k, "bytes": v} for k, v in top_convos],
        "anomalies":          anomalies,
        "total_flows":        len(_ip_flows),
        "total_packets":      _total,
        "capture_active":     _sniffing,
    }


@app.get("/api/v1/investigate/{ip}")
async def investigate(ip: str) -> dict:
    cached = _devices.get(ip)
    loop   = asyncio.get_event_loop()

    if cached:
        ports   = cached.get("ports", [])
        os_name = cached.get("os", "")
        hostname = cached.get("hostname", ip)
        vendor   = cached.get("vendor", "")
        rscore   = cached.get("riskScore", 0)
        category = cached.get("dpiCategory", "")
        fw       = cached.get("firewallStatus", "Unknown")
    else:
        ports    = await loop.run_in_executor(None, _scan_ports, ip)
        os_name  = await loop.run_in_executor(None, _fingerprint_os, ip)
        hostname = _resolve_hostname(ip)
        vendor   = ""
        rscore   = _risk_score(ports, vendor, os_name)
        category = _classify(ports, hostname, vendor, os_name)
        fw       = "Unknown"

    svc_vers = await loop.run_in_executor(None, _service_versions, ip, ports)

    # Live connections for this IP
    active_conns = []
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.raddr and (c.raddr.ip == ip or (c.laddr and c.laddr.ip == ip)):
                active_conns.append({
                    "local":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status,
                    "pid":    c.pid,
                })
    except Exception:
        pass

    flow = _ip_flows.get(ip, {})
    related_pkts   = [p for p in list(_packets) if p.get("src_ip") == ip or p.get("dst_ip") == ip][-30:]
    related_alerts = [a for a in list(_alerts) if a.get("source_ip") == ip or ip in a.get("description", "")]
    outbound_ports = list(flow.get("ports", set()))[:20]

    return {
        "ip":               ip,
        "hostname":         hostname,
        "os":               os_name,
        "vendor":           vendor,
        "ports":            ports,
        "port_services":    {p: PORT_SERVICES.get(p, "Unknown") for p in ports},
        "service_versions": svc_vers,
        "risk_score":       rscore,
        "category":         category,
        "firewall":         fw,
        "active_connections": active_conns,
        "flow_stats":       {"tx_bytes": flow.get("tx", 0), "rx_bytes": flow.get("rx", 0), "packets": flow.get("packets", 0)},
        "outbound_ports":   outbound_ports,
        "recent_packets":   related_pkts,
        "related_alerts":   related_alerts,
        "last_seen":        flow.get("last_seen", datetime.now().isoformat()),
        "timestamp":        datetime.now().isoformat(),
    }


class ScanReq(BaseModel):
    interface: str = ""
    subnet:    str = ""
    method:    str = "arp"


@app.post("/api/v1/scanner/discover")
async def discover(req: ScanReq) -> dict:
    iface  = req.interface or default_interface()
    subnet = req.subnet    or local_subnet()
    log.info(f"Scan: method={req.method} subnet={subnet} iface={iface}")

    raw: List[dict] = []

    if req.method == "arp":
        if not SCAPY_OK:
            raise HTTPException(400, "scapy not installed. Use method=icmp instead.")
        if os.geteuid() != 0:
            raise HTTPException(403, "Root required for ARP scan. Installer sets up sudoers.d automatically.")
        try:
            pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=subnet)
            answered, _ = scapy.srp(pkt, timeout=4, iface=iface, verbose=False)
            raw = [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]
        except Exception as e:
            raise HTTPException(500, f"ARP scan error: {e}")
    else:
        # ICMP / SYN via nmap
        out = _run(["nmap", "-sn", "-T4", "--max-retries", "1", subnet], timeout=60)
        if not out:
            raise HTTPException(500, "nmap not found or returned no output. Install: sudo apt install nmap")
        for line in out.splitlines():
            m_ip  = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            m_mac = re.search(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", line.upper())
            if m_ip:
                raw.append({
                    "ip":  m_ip.group(1),
                    "mac": m_mac.group(1) if m_mac else "00:00:00:00:00:00",
                })

    # Deduplicate
    seen: set = set()
    deduped = []
    for h in raw:
        if h["ip"] not in seen:
            seen.add(h["ip"])
            deduped.append(h)

    # Enrich in thread pool
    loop = asyncio.get_event_loop()
    enriched = []
    for h in deduped:
        try:
            rec = await loop.run_in_executor(None, enrich_host, h["ip"], h["mac"])
            _devices[h["ip"]] = rec
            _generate_ids(rec)
            enriched.append(rec)
        except Exception as e:
            log.error(f"Enrich {h['ip']}: {e}")

    alerts_generated = sum(
        1 for a in _alerts
        if any(d["ip"] in a.get("source_ip", "") for d in enriched)
    )
    return {
        "hosts_found":       len(enriched),
        "devices":           enriched,
        "alerts_generated":  alerts_generated,
    }


@app.get("/api/v1/scanner/interfaces")
def interfaces() -> dict:
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    ifaces = []
    for name, stat in stats.items():
        ipv4 = next(
            (a.address for a in addrs.get(name, []) if a.family == socket.AF_INET),
            None
        )
        ifaces.append({
            "name": name, "is_up": stat.isup,
            "speed_mbps": stat.speed, "mtu": stat.mtu, "ipv4": ipv4,
        })
    return {"interfaces": ifaces, "default": default_interface(), "local_ip": local_ip()}


class FwReq(BaseModel):
    ip_address: str
    action:     str
    driver:     str = "iptables"


@app.post("/api/v1/firewall/inject")
async def firewall_inject(req: FwReq) -> dict:
    if os.geteuid() != 0:
        raise HTTPException(403, "Root required to modify firewall rules")
    ip, action = req.ip_address, req.action.lower()
    if action == "block":
        cmds = [
            ["iptables", "-I", "INPUT",  "-s", ip, "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]
    elif action == "allow":
        cmds = [
            ["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"],
            ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]
    else:
        raise HTTPException(400, f"Unknown action: {action}")

    results = []
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            results.append({"cmd": " ".join(cmd), "rc": r.returncode, "err": r.stderr.strip()})
        except Exception as e:
            results.append({"cmd": " ".join(cmd), "rc": -1, "err": str(e)})

    if ip in _devices:
        _devices[ip]["firewallStatus"] = "Blocked" if action == "block" else "Allowed"

    return {"ip": ip, "action": action, "results": results}


@app.get("/api/v1/firewall/rules")
def firewall_rules() -> dict:
    try:
        r = subprocess.run(
            ["iptables", "-L", "INPUT", "-n", "-v", "--line-numbers"],
            capture_output=True, text=True, timeout=5
        )
        return {"rules": r.stdout, "error": r.stderr}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/v1/connections")
def connections() -> dict:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                conns.append({
                    "local_addr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status,
                    "pid":    c.pid,
                    "family": str(c.family),
                    "type":   str(c.type),
                })
            except Exception:
                pass
    except Exception as e:
        log.warning(f"net_connections error: {e}")
    return {"connections": conns, "count": len(conns)}


@app.get("/api/v1/packets")
def packets(limit: int = 100) -> dict:
    return {
        "packets": list(_packets)[-limit:],
        "total":   _total,
        "sniffer_active": _sniffing,
    }


@app.post("/api/v1/sniffer/start")
def sniffer_start(interface: str = "") -> dict:
    if not SCAPY_OK:
        raise HTTPException(400, "scapy not installed")
    if os.geteuid() != 0:
        raise HTTPException(403, "Root required for packet capture")
    iface = interface or default_interface()
    start_sniffer(iface)
    return {"status": "started", "interface": iface}


@app.post("/api/v1/sniffer/stop")
def sniffer_stop() -> dict:
    stop_sniffer()
    return {"status": "stopped"}


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Graceful shutdown on SIGTERM / SIGINT
    def _shutdown(sig, frame):
        log.info(f"Signal {sig} received — shutting down")
        stop_sniffer()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    uvicorn.run(
        "app:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
        access_log=True,
    )
