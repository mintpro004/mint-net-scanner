"""
Mint Net Scanner v3.0 — Production Backend Daemon
Force-root: capabilities always granted by installer.
New: full device details, network name/SSID, traffic analysis, deep investigate.
"""

import asyncio, json, logging, os, re, socket, subprocess, threading, time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import psutil, uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import scapy.all as scapy
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

try:
    import nmap as _nmap
    NMAP_OK = True
except Exception:
    NMAP_OK = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mint")

# ── Load .env ─────────────────────────────────────────────────────────────────
def _load_env():
    p = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(p):
        for line in open(p):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
_load_env()

HOST      = os.environ.get("MINT_HOST", "0.0.0.0")
PORT      = int(os.environ.get("MINT_PORT", "8000"))
DEF_IFACE = os.environ.get("MINT_INTERFACE", "")
DEF_SUBNET= os.environ.get("MINT_SUBNET", "")
ENV_SSID  = os.environ.get("MINT_SSID", "")

app = FastAPI(title="Mint Net Scanner", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── State ─────────────────────────────────────────────────────────────────────
_packets:  deque = deque(maxlen=400)        # Slightly reduced for memory
_alerts:   deque = deque(maxlen=200)        # Reduced for memory
_devices:  Dict[str, dict] = {}
_traffic_stats: deque = deque(maxlen=60)    # 1 min history
_proto_counts: Dict[str, int] = defaultdict(int)
_ip_flows: Dict[str, dict] = defaultdict(lambda: {"tx": 0, "rx": 0, "packets": 0, "ports": set(), "last_seen": ""})
_bps = _pps = _total = 0
_sniffing = False
_sniff_thread: Optional[threading.Thread] = None
_last_bps_ts = time.time()
_last_bps_bytes = 0

def _cleanup_state():
    """Periodically clear old IP flows and stale data to save memory."""
    while True:
        try:
            time.sleep(300) # every 5 mins
            now = datetime.now()
            stale_ips = []
            for ip, data in _ip_flows.items():
                if data.get("last_seen"):
                    ls = datetime.fromisoformat(data["last_seen"])
                    if (now - ls).total_seconds() > 3600: # 1 hour stale
                        stale_ips.append(ip)
            for ip in stale_ips:
                del _ip_flows[ip]
        except Exception: pass

# ── Network helpers ───────────────────────────────────────────────────────────
def _run(cmd, timeout=5, **kw):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout, text=True, **kw)
    except Exception:
        return ""

def default_interface() -> str:
    if DEF_IFACE: return DEF_IFACE
    out = _run(["ip", "route", "get", "8.8.8.8"])
    m = re.search(r"dev\s+(\S+)", out)
    if m: return m.group(1)
    for iface, stat in psutil.net_if_stats().items():
        if iface != "lo" and stat.isup:
            return iface
    return "eth0"

def local_ip() -> str:
    out = _run(["ip", "route", "get", "8.8.8.8"])
    m = re.search(r"src\s+([\d.]+)", out)
    if m: return m.group(1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception: return "127.0.0.1"

def local_subnet() -> str:
    if DEF_SUBNET: return DEF_SUBNET
    ip = local_ip(); pts = ip.split(".")
    return f"{pts[0]}.{pts[1]}.{pts[2]}.0/24"

def get_ssid() -> str:
    """Try multiple methods to get current WiFi SSID."""
    if ENV_SSID and ENV_SSID not in ("", "Unknown Network"):
        return ENV_SSID
    iface = default_interface()
    for cmd in [
        ["iwgetid", "-r"],
        ["iwgetid", iface, "-r"],
        ["iw", "dev", iface, "link"],
        ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
        ["wpa_cli", "-i", iface, "status"],
    ]:
        try:
            out = _run(cmd)
            if not out: continue
            if "SSID" in out:
                m = re.search(r"SSID:\s*(.+)", out)
                if m: return m.group(1).strip()
            if "ssid=" in out.lower():
                m = re.search(r"(?i)ssid=(.+)", out)
                if m: return m.group(1).strip()
            if "yes:" in out:
                return out.split("yes:")[-1].strip()
            val = out.strip().split("\n")[0]
            if val and len(val) < 64: return val
        except Exception:
            pass
    # Check if wired
    stat = psutil.net_if_stats().get(iface)
    if stat and iface.startswith("e"):
        return f"Wired — {iface}"
    return "Local Network"

def get_network_details() -> dict:
    """Full details about the current network connection."""
    iface = default_interface()
    ip    = local_ip()
    addrs = psutil.net_if_addrs().get(iface, [])
    stats = psutil.net_if_stats().get(iface)
    gateway = ""
    dns_servers = []

    # Gateway
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via ([\d.]+)", out)
    if m: gateway = m.group(1)

    # DNS
    for f in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"]:
        if os.path.exists(f):
            for line in open(f):
                m = re.match(r"nameserver\s+([\d.a-f:]+)", line)
                if m: dns_servers.append(m.group(1))
            break

    # IP info per family
    ipv4_info = next((a for a in addrs if a.family == socket.AF_INET), None)
    ipv6_info = next((a for a in addrs if a.family == socket.AF_INET6), None)
    mac_info  = next((a for a in addrs if a.family == psutil.AF_LINK), None)

    # WiFi signal strength
    signal_dbm = None
    try:
        out = _run(["iw", "dev", iface, "station", "dump"])
        m = re.search(r"signal:\s+([-\d]+)", out)
        if m: signal_dbm = int(m.group(1))
    except Exception: pass

    # Speed / link info
    link_speed = 0
    if stats: link_speed = stats.speed

    return {
        "ssid":       get_ssid(),
        "interface":  iface,
        "ipv4":       ipv4_info.address if ipv4_info else ip,
        "netmask":    ipv4_info.netmask if ipv4_info else "",
        "ipv6":       ipv6_info.address if ipv6_info else "",
        "mac":        mac_info.address.upper() if mac_info else "",
        "gateway":    gateway,
        "dns":        dns_servers[:3],
        "subnet":     local_subnet(),
        "link_speed": link_speed,
        "signal_dbm": signal_dbm,
        "is_up":      stats.isup if stats else False,
        "mtu":        stats.mtu if stats else 1500,
        "type":       "WiFi" if iface.startswith("w") else "Ethernet" if iface.startswith("e") else "Unknown",
    }

def resolve_hostname(ip: str) -> str:
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return ip

def mac_vendor(mac: str) -> str:
    prefix = mac.upper().replace(":","").replace("-","")[:6]
    for path in ["/usr/share/ieee-data/oui.txt", "/usr/share/nmap/nmap-mac-prefixes",
                 "/var/lib/ieee-data/oui.txt"]:
        if os.path.exists(path):
            out = _run(["grep", "-im", "1", prefix, path], timeout=2)
            if out:
                parts = out.split("\t")
                return parts[-1].strip() if len(parts) > 1 else out.split("(")[-1].rstrip(")").strip()
    return "Unknown Vendor"

def scan_ports(ip: str) -> List[int]:
    if not NMAP_OK: return []
    try:
        nm = _nmap.PortScanner()
        nm.scan(ip, ports="21,22,23,25,53,80,110,143,443,445,554,1883,3389,5900,8000,8080,8443,2049,5000,9100",
                arguments="-T4 --open --max-retries 1", timeout=25)
        if ip in nm.all_hosts():
            return sorted([p for proto in nm[ip].all_protocols()
                           for p in nm[ip][proto] if nm[ip][proto][p]["state"] == "open"])
    except Exception as e:
        log.debug(f"Port scan {ip}: {e}")
    return []

def get_port_services(ports: List[int]) -> Dict[int, str]:
    """Map port numbers to service names."""
    known = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP",
        110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB", 554:"RTSP",
        1883:"MQTT", 3389:"RDP", 5900:"VNC", 8000:"HTTP-Alt", 8080:"HTTP-Proxy",
        8443:"HTTPS-Alt", 2049:"NFS", 5000:"UPnP", 9100:"Print",
    }
    return {p: known.get(p, "Unknown") for p in ports}

def fingerprint_os(ip: str) -> str:
    if not NMAP_OK: return "Unknown OS"
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

def nmap_scripts(ip: str, ports: List[int]) -> dict:
    """Run nmap service/version detection and vuln scripts."""
    if not NMAP_OK or not ports: return {}
    try:
        nm = _nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports[:10])
        nm.scan(ip, ports=port_str, arguments="-sV --version-light -T4 --max-retries 1", timeout=30)
        services = {}
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for p in nm[ip][proto]:
                    info = nm[ip][proto][p]
                    services[p] = {
                        "name":    info.get("name",""),
                        "product": info.get("product",""),
                        "version": info.get("version",""),
                        "extra":   info.get("extrainfo",""),
                    }
        return services
    except Exception:
        return {}

def risk_score(ports: List[int], vendor: str, os_name: str) -> int:
    score = 0
    risky = {23:40, 21:30, 3389:30, 5900:25, 554:20, 8000:10, 80:5, 8080:8, 445:20, 1883:15}
    for p in ports: score += risky.get(p, 0)
    low_vendors = ["hikvision","dahua","tp-link","shenzhen","hangzhou","realtek"]
    if any(v in vendor.lower() for v in low_vendors): score += 20
    if "windows xp" in os_name.lower() or "windows 7" in os_name.lower(): score += 25
    if "android" in os_name.lower(): score += 10
    return min(score, 100)

def classify_device(ports: List[int], hostname: str, vendor: str, os_name: str) -> str:
    h, v, o = hostname.lower(), vendor.lower(), os_name.lower()
    if any(p in ports for p in [554, 8000]) or any(k in h for k in ["cam","dvr","nvr"]): return "IoT / Camera"
    if any(p in ports for p in [2049, 5000]) or "synology" in v or "qnap" in v: return "NAS / Storage"
    if 53 in ports or 67 in ports or any(k in h for k in ["router","gateway","gw"]): return "Router / Gateway"
    if 3389 in ports or 5900 in ports: return "Windows Workstation"
    if 22 in ports and "linux" in o: return "Linux Server"
    if 445 in ports and "windows" in o: return "Windows Server"
    if 1883 in ports: return "IoT / MQTT Broker"
    if 9100 in ports: return "Network Printer"
    if "android" in o or "iphone" in o.lower(): return "Mobile Device"
    if "raspberry" in v.lower() or "raspberry" in h: return "Raspberry Pi"
    return "Endpoint"

def enrich(ip: str, mac: str) -> dict:
    hostname  = resolve_hostname(ip)
    vendor    = mac_vendor(mac)
    ports     = scan_ports(ip)
    os_name   = fingerprint_os(ip)
    services  = nmap_scripts(ip, ports)
    port_svcs = get_port_services(ports)
    rscore    = risk_score(ports, vendor, os_name)
    category  = classify_device(ports, hostname, vendor, os_name)

    # Firewall status
    fw = "Allowed"
    try:
        r = subprocess.run(["iptables","-C","INPUT","-s",ip,"-j","DROP"], capture_output=True, timeout=2)
        if r.returncode == 0: fw = "Blocked"
    except Exception: pass

    # Active connections to/from this IP
    conns = [c for c in psutil.net_connections(kind="tcp")
             if c.raddr and c.raddr.ip == ip and c.status == "ESTABLISHED"]

    # Traffic stats from flow tracker
    flow = _ip_flows.get(ip, {})

    return {
        "id": ip, "ip": ip, "mac": mac.upper(), "hostname": hostname,
        "vendor": vendor, "os": os_name, "status": "online",
        "dpiCategory": category,
        "activeConnections": len(conns),
        "connectionDetails": [{"local": f"{c.laddr.ip}:{c.laddr.port}", "remote": f"{c.raddr.ip}:{c.raddr.port}"} for c in conns[:5]],
        "txBytes": flow.get("tx", 0), "rxBytes": flow.get("rx", 0),
        "packetCount": flow.get("packets", 0),
        "riskScore": rscore,
        "ports": ports,
        "portServices": port_svcs,
        "serviceVersions": services,
        "firewallStatus": fw,
        "lastSeen": datetime.now().isoformat(),
        "firstSeen": datetime.now().isoformat(),
    }

def generate_ids(device: dict):
    ip = device["ip"]
    ports = device.get("ports", [])
    risky_ports = [p for p in ports if p in [23,21,3389,5900,554,8000,445,1883]]

    def add_alert(aid, sev, ttype, desc):
        if not any(a["id"] == aid for a in _alerts):
            _alerts.append({"id": aid, "severity": sev, "threat_type": ttype,
                "description": desc, "source_ip": ip, "destination_ip": "Any",
                "timestamp": datetime.now().isoformat()})

    if risky_ports:
        svcs = device.get("portServices", {})
        svc_list = ", ".join(f"{p}/{svcs.get(p,'?')}" for p in risky_ports)
        add_alert(f"ids_{ip}_ports",
            "CRITICAL" if len(risky_ports) >= 3 else "HIGH",
            "Dangerous Open Ports",
            f"{ip} ({device['hostname']}) exposes {len(risky_ports)} high-risk port(s): {svc_list}")

    if device.get("dpiCategory") == "IoT / Camera":
        add_alert(f"ids_{ip}_iot", "HIGH", "Unsecured IoT Device",
            f"Camera/IoT device {ip} ({device['vendor']}) detected. Verify default credentials and firmware.")

    if 23 in ports:
        add_alert(f"ids_{ip}_telnet", "CRITICAL", "Telnet Enabled",
            f"{ip} has Telnet (port 23) open — unencrypted remote access protocol. Disable immediately.")

    if 445 in ports:
        add_alert(f"ids_{ip}_smb", "HIGH", "SMB Port Exposed",
            f"{ip} has SMB (port 445) open — potential ransomware/lateral movement vector.")

    if device.get("riskScore", 0) >= 65:
        add_alert(f"ids_{ip}_highrisk", "CRITICAL", "High Risk Host",
            f"{ip} risk score: {device['riskScore']}/100. Immediate review recommended.")

# ── Packet Sniffer ────────────────────────────────────────────────────────────
def _pkt_cb(pkt):
    global _bps, _pps, _total
    _total += 1
    size = len(pkt)
    _bps = int(_bps * 0.85 + size * 8 * 0.15)
    _pps = int(_pps * 0.85 + 1 * 0.15) or 1

    src = dst = proto = "?"
    sport = dport = 0
    try:
        if pkt.haslayer("IP"):
            src, dst = pkt["IP"].src, pkt["IP"].dst
            # Track per-IP flow
            _ip_flows[src]["tx"] += size
            _ip_flows[dst]["rx"] += size
            _ip_flows[src]["packets"] += 1
            _ip_flows[src]["last_seen"] = datetime.now().isoformat()
        if pkt.haslayer("TCP"):
            sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
            proto = "TCP"
            _ip_flows[src]["ports"].add(dport)
        elif pkt.haslayer("UDP"):
            sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
            proto = "UDP"
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"
        elif pkt.haslayer("ARP"):
            proto = "ARP"
            if pkt.haslayer("ARP"):
                src = pkt["ARP"].psrc or src
                dst = pkt["ARP"].pdst or dst
    except Exception:
        pass

    _proto_counts[proto] += 1

    info_str = ""
    try:
        if dport == 80  and pkt.haslayer("Raw"): info_str = "HTTP"
        elif dport == 443: info_str = "HTTPS"
        elif dport == 53:  info_str = "DNS query"
        elif proto == "ICMP": info_str = "Ping/ICMP"
        else: info_str = f"Port {sport}→{dport}" if dport else ""
    except Exception:
        pass

    _packets.append({
        "id": f"p{_total}", "timestamp": datetime.now().strftime("%H:%M:%S"),
        "protocol": proto, "src_ip": src, "dst_ip": dst,
        "sport": sport, "dport": dport,
        "packet_size": size,
        "info": info_str or f"Frame #{_total}",
    })

    # IDS: port scan heuristic
    my_ip = local_ip()
    if src != my_ip:  # Whitelist scanner's own IP
        recent = [p for p in list(_packets)[-40:] if p.get("src_ip") == src]
        unique_dports = {p["dport"] for p in recent if p.get("dport")}
        if len(unique_dports) > 15:
            aid = f"ids_portscan_{src}"
            if not any(a["id"] == aid for a in _alerts):
                _alerts.append({"id": aid, "severity": "HIGH", "threat_type": "Port Scan",
                    "description": f"{src} scanned {len(unique_dports)} distinct ports in <40 packets.",
                    "source_ip": src, "destination_ip": "*",
                    "timestamp": datetime.now().isoformat()})

    # IDS: broadcast storms
    if dst in ("255.255.255.255", "224.0.0.1") and _pps > 500:
        aid = f"ids_broadcast_{src}"
        if not any(a["id"] == aid for a in _alerts):
            _alerts.append({"id": aid, "severity": "MEDIUM", "threat_type": "Broadcast Storm",
                "description": f"High broadcast rate from {src} ({_pps} pps).",
                "source_ip": src, "destination_ip": dst,
                "timestamp": datetime.now().isoformat()})

def _traffic_sampler():
    """Background thread: saves 1-second traffic snapshots for analysis."""
    while True:
        try:
            time.sleep(1)
            net = psutil.net_io_counters()
            _traffic_stats.append({
                "ts":    datetime.now().isoformat(),
                "bps":   _bps,
                "pps":   _pps,
                "bytes_sent": net.bytes_sent,
                "bytes_recv": net.bytes_recv,
                "proto_counts": dict(_proto_counts),
            })
        except Exception: pass

async def _auto_discovery():
    """Periodically scan for new devices in the background."""
    await asyncio.sleep(5) # wait for startup
    while True:
        try:
            subnet = local_subnet()
            iface = default_interface()
            log.info(f"Background auto-discovery on {subnet}...")
            
            # Simple ARP ping for discovery
            if SCAPY_OK and os.geteuid() == 0:
                pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=subnet)
                answered, _ = scapy.srp(pkt, timeout=4, iface=iface, verbose=False)
                found = [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]
            else:
                out = _run(["nmap","-sn","-T4","--max-retries","1",subnet], timeout=60)
                found = []
                for line in out.splitlines():
                    m_ip  = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    m_mac = re.search(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", line.upper())
                    if m_ip: found.append({"ip": m_ip.group(1), "mac": m_mac.group(1) if m_mac else "00:00:00:00:00:00"})

            # Enrich only new devices or those not updated in 30 mins
            for h in found:
                ip = h["ip"]
                existing = _devices.get(ip)
                if not existing or (datetime.now() - datetime.fromisoformat(existing["lastSeen"])).total_seconds() > 1800:
                    rec = await asyncio.get_event_loop().run_in_executor(None, enrich, ip, h["mac"])
                    _devices[ip] = rec
                    generate_ids(rec)
            
        except Exception as e:
            log.error(f"Auto-discovery error: {e}")
        
        await asyncio.sleep(600) # Run every 10 minutes

def _sniff_loop(iface: str):
    global _sniffing
    _sniffing = True
    log.info(f"Packet capture started on {iface}")
    try:
        scapy.sniff(iface=iface, prn=_pkt_cb, store=False,
                    stop_filter=lambda _: not _sniffing)
    except Exception as e:
        log.error(f"Sniffer error: {e}")
    finally:
        _sniffing = False

def start_sniffer(iface: str):
    global _sniff_thread
    if not SCAPY_OK: log.warning("scapy unavailable"); return
    if _sniffing: return
    _sniff_thread = threading.Thread(target=_sniff_loop, args=(iface,), daemon=True)
    _sniff_thread.start()

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    iface = default_interface()
    log.info(f"Mint Net Scanner v3.0 | iface={iface} | root={os.geteuid()==0} | scapy={SCAPY_OK} | nmap={NMAP_OK}")
    threading.Thread(target=_traffic_sampler, daemon=True).start()
    threading.Thread(target=_cleanup_state, daemon=True).start()
    asyncio.create_task(_auto_discovery())
    if SCAPY_OK and os.geteuid() == 0:
        start_sniffer(iface)
    else:
        log.warning("Run as root for packet capture. Installer should have set up sudoers.d — try: sudo python app.py")

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    net = get_network_details()
    return {"status":"ok", "version":"3.0.0", "scapy":SCAPY_OK, "nmap":NMAP_OK,
            "running_as_root": os.geteuid()==0, "sniffer_active":_sniffing,
            "default_interface": default_interface(), "local_subnet": local_subnet(),
            "local_ip": local_ip(), "ssid": net["ssid"], "timestamp": datetime.now().isoformat()}

@app.get("/api/v1/metrics")
async def metrics():
    net = psutil.net_io_counters(); ram = psutil.virtual_memory()
    devs = list(_devices.values())
    for d in devs:
        d["activeConnections"] = sum(1 for c in psutil.net_connections(kind="tcp")
                                     if c.raddr and c.raddr.ip == d["ip"] and c.status=="ESTABLISHED")
        d["lastSeen"] = datetime.now().isoformat()
        flow = _ip_flows.get(d["ip"], {})
        d["txBytes"] = flow.get("tx", d.get("txBytes",0))
        d["rxBytes"]  = flow.get("rx", d.get("rxBytes",0))
    return {
        "cpu_percent":    round(psutil.cpu_percent(interval=0.1),1),
        "ram_percent":    round(ram.percent,1),
        "ram_used_gb":    round(ram.used/1e9,2),
        "ram_total_gb":   round(ram.total/1e9,2),
        "current_bps":    _bps,
        "current_pps":    _pps,
        "total_packet_count": _total,
        "bytes_sent":     net.bytes_sent,
        "bytes_recv":     net.bytes_recv,
        "active_devices": devs,
        "active_threats": list(_alerts),
        "live_packet_flows": list(_packets)[-50:],
        "proto_counts":   dict(_proto_counts),
        "sniffer_active": _sniffing,
        "scapy_available": SCAPY_OK,
        "nmap_available": NMAP_OK,
        "timestamp":      datetime.now().isoformat(),
    }

@app.get("/api/v1/network")
def network_info():
    return get_network_details()

@app.get("/api/v1/traffic/analysis")
def traffic_analysis():
    """Deep traffic analysis: top talkers, protocol breakdown, anomalies."""
    samples = list(_traffic_stats)

    # Top talkers by bytes
    top_tx = sorted(_ip_flows.items(), key=lambda x: x[1].get("tx",0), reverse=True)[:10]
    top_rx = sorted(_ip_flows.items(), key=lambda x: x[1].get("rx",0), reverse=True)[:10]

    # Protocol breakdown
    total_pkts = sum(_proto_counts.values()) or 1
    proto_pct = {k: round(v/total_pkts*100,1) for k,v in sorted(_proto_counts.items(), key=lambda x:-x[1])}

    # BPS history (last 60 samples)
    bps_history = [{"ts": s["ts"][-8:], "bps": s["bps"], "pps": s["pps"]} for s in samples[-60:]]

    # Anomaly detection
    anomalies = []
    if len(samples) >= 10:
        recent_pps = [s["pps"] for s in samples[-10:]]
        avg_pps = sum(recent_pps)/len(recent_pps)
        if avg_pps > 1000:
            anomalies.append({"type":"High PPS", "detail": f"Average {avg_pps:.0f} pps over last 10s", "severity":"HIGH"})

    # Conversation pairs (src→dst)
    conversations = defaultdict(int)
    for p in list(_packets)[-200:]:
        if p["src_ip"] != "?" and p["dst_ip"] != "?":
            key = f"{p['src_ip']} → {p['dst_ip']}"
            conversations[key] += p["packet_size"]
    top_convos = sorted(conversations.items(), key=lambda x: -x[1])[:10]

    return {
        "top_talkers_tx":    [{"ip": ip, "bytes": d.get("tx",0), "packets": d.get("packets",0)} for ip,d in top_tx],
        "top_talkers_rx":    [{"ip": ip, "bytes": d.get("rx",0)} for ip,d in top_rx],
        "protocol_breakdown": proto_pct,
        "bps_history":       bps_history,
        "top_conversations": [{"pair": k, "bytes": v} for k,v in top_convos],
        "anomalies":         anomalies,
        "total_flows":       len(_ip_flows),
        "total_packets":     _total,
        "capture_active":    _sniffing,
    }

@app.get("/api/v1/investigate/{ip}")
async def investigate(ip: str):
    """Full deep investigation of a specific host."""
    cached = _devices.get(ip)
    ports  = cached.get("ports",[]) if cached else scan_ports(ip)
    os_name = cached.get("os","") if cached else fingerprint_os(ip)
    services = nmap_scripts(ip, ports)
    hostname = cached.get("hostname","") if cached else resolve_hostname(ip)
    vendor   = cached.get("mac","") if cached else ""
    if vendor: vendor = mac_vendor(vendor.replace(":","")[:6] + "000000")

    # Active connections
    active_conns = [
        {"local": f"{c.laddr.ip}:{c.laddr.port}", "remote": f"{c.raddr.ip}:{c.raddr.port}", "status": c.status, "pid": c.pid}
        for c in psutil.net_connections(kind="tcp")
        if c.raddr and (c.raddr.ip == ip or (c.laddr and c.laddr.ip == ip))
    ]

    # Flow data
    flow = _ip_flows.get(ip, {})

    # Recent packets involving this IP
    related_packets = [p for p in list(_packets) if p.get("src_ip")==ip or p.get("dst_ip")==ip][-30:]

    # Related alerts
    related_alerts = [a for a in list(_alerts) if a.get("source_ip")==ip or ip in a.get("description","")]

    # Unique destination ports from this IP
    outbound_ports = list(flow.get("ports", set()))[:20]

    return {
        "ip":             ip,
        "hostname":       hostname,
        "os":             os_name,
        "vendor":         vendor,
        "ports":          ports,
        "port_services":  get_port_services(ports),
        "service_versions": services,
        "risk_score":     cached.get("riskScore",0) if cached else risk_score(ports, vendor, os_name),
        "category":       cached.get("dpiCategory","") if cached else classify_device(ports, hostname, vendor, os_name),
        "firewall":       cached.get("firewallStatus","") if cached else "Unknown",
        "active_connections": active_conns,
        "flow_stats":     {"tx_bytes": flow.get("tx",0), "rx_bytes": flow.get("rx",0), "packets": flow.get("packets",0)},
        "outbound_ports": outbound_ports,
        "recent_packets": related_packets,
        "related_alerts": related_alerts,
        "last_seen":      flow.get("last_seen", datetime.now().isoformat()),
        "timestamp":      datetime.now().isoformat(),
    }

@app.get("/api/v1/dns/check/{ip}")
async def dns_check(ip: str):
    """Deep check for DNS vulnerabilities (recursion, amplification)."""
    if not SCAPY_OK or os.geteuid() != 0:
        raise HTTPException(400, "Root/Scapy required for DNS deep check")
    
    results = {"recursion": False, "amplification": False, "details": ""}
    
    try:
        # Test recursion: Query for a non-local domain
        dns_req = scapy.IP(dst=ip)/scapy.UDP(dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com"))
        ans = scapy.sr1(dns_req, timeout=2, verbose=False)
        
        if ans and ans.haslayer("DNS"):
            if ans["DNS"].ancount > 0:
                results["recursion"] = True
                results["details"] += "Recursion enabled: Server resolved google.com. "
            
            # Amplification check (simplified): Response size > Request size
            if len(ans) > len(dns_req) * 2:
                results["amplification"] = True
                results["details"] += f"Potential amplification: Response is {len(ans)} bytes (req: {len(dns_req)})."
                
    except Exception as e:
        results["details"] = f"Check failed: {e}"
        
    return results

class ScanReq(BaseModel):
    interface: str = ""
    subnet:    str = ""
    method:    str = "arp"

@app.post("/api/v1/scanner/discover")
async def scan(req: ScanReq):
    iface  = req.interface or default_interface()
    subnet = req.subnet    or local_subnet()
    log.info(f"Scan: {req.method} on {subnet} via {iface}")

    if req.method == "arp":
        if not SCAPY_OK: raise HTTPException(400, "scapy not installed — use icmp method")
        if os.geteuid() != 0: raise HTTPException(403, "Root required. Installer should have set up sudoers.d.")
        pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=subnet)
        answered, _ = scapy.srp(pkt, timeout=4, iface=iface, verbose=False)
        raw = [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]
    else:
        out = _run(["nmap","-sn","-T4","--max-retries","1",subnet], timeout=60)
        raw = []
        for line in out.splitlines():
            m_ip  = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            m_mac = re.search(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", line.upper())
            if m_ip: raw.append({"ip": m_ip.group(1), "mac": m_mac.group(1) if m_mac else "00:00:00:00:00:00"})

    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, enrich, h["ip"], h["mac"]) for h in raw]
    enriched = await asyncio.gather(*tasks)

    for rec in enriched:
        _devices[rec["ip"]] = rec
        generate_ids(rec)

    return {"hosts_found": len(enriched), "devices": enriched,
            "alerts_generated": sum(1 for a in _alerts if any(d["ip"] in a.get("source_ip","") for d in enriched))}

@app.get("/api/v1/scanner/interfaces")
def interfaces():
    stats = psutil.net_if_stats(); addrs = psutil.net_if_addrs()
    ifaces = []
    for name, stat in stats.items():
        ipv4 = next((a.address for a in addrs.get(name,[]) if a.family==socket.AF_INET), None)
        ifaces.append({"name":name,"is_up":stat.isup,"speed_mbps":stat.speed,"mtu":stat.mtu,"ipv4":ipv4})
    return {"interfaces":ifaces,"default":default_interface(),"local_ip":local_ip()}

class FwReq(BaseModel):
    ip_address: str; action: str; driver: str = "iptables"

@app.post("/api/v1/firewall/inject")
async def firewall(req: FwReq):
    if os.geteuid() != 0: raise HTTPException(403, "Root required")
    ip, action = req.ip_address, req.action.lower()
    cmds = ([["iptables","-I","INPUT","-s",ip,"-j","DROP"],["iptables","-I","OUTPUT","-d",ip,"-j","DROP"]]
            if action=="block" else
            [["iptables","-D","INPUT","-s",ip,"-j","DROP"],["iptables","-D","OUTPUT","-d",ip,"-j","DROP"]])
    results = []
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        results.append({"cmd":" ".join(cmd),"rc":r.returncode,"err":r.stderr.strip()})
    if ip in _devices:
        _devices[ip]["firewallStatus"] = "Blocked" if action=="block" else "Allowed"
    return {"ip":ip,"action":action,"results":results}

@app.get("/api/v1/firewall/rules")
def fw_rules():
    try:
        r = subprocess.run(["iptables","-L","INPUT","-n","-v","--line-numbers"], capture_output=True, text=True, timeout=5)
        return {"rules":r.stdout,"error":r.stderr}
    except Exception as e: raise HTTPException(500, str(e))

@app.get("/api/v1/connections")
def connections():
    conns = []
    for c in psutil.net_connections(kind="inet"):
        try:
            conns.append({"local_addr":f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                          "remote_addr":f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                          "status":c.status,"pid":c.pid})
        except Exception: pass
    return {"connections":conns,"count":len(conns)}

@app.get("/api/v1/packets")
def packets(limit: int = 100):
    return {"packets":list(_packets)[-limit:],"total":_total,"sniffer_active":_sniffing}

@app.post("/api/v1/sniffer/start")
def sniffer_start(interface: str = ""):
    if not SCAPY_OK: raise HTTPException(400,"scapy not installed")
    if os.geteuid() != 0: raise HTTPException(403,"Root required")
    start_sniffer(interface or default_interface())
    return {"status":"started"}

@app.post("/api/v1/sniffer/stop")
def sniffer_stop():
    global _sniffing; _sniffing = False; return {"status":"stopped"}

if __name__ == "__main__":
    uvicorn.run("app:app", host=HOST, port=PORT, reload=False, log_level="info")
