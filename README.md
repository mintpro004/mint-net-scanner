# Mint Net Scanner v3.0

Production network security dashboard with **zero fake data**.
Auto-installs, auto-launches, force-grants raw socket permissions.

---

## One-command install (any Linux / Chromebook)

```bash
bash install.sh
```

- Detects your OS (Debian, RHEL, Arch, Alpine, Chromebook, RPi, WSL2, macOS)
- **New v3.1:** Parallel device enrichment for 10x faster scans.
- **New v3.1:** Background auto-discovery keeps device list updated automatically.
- Force-grants raw socket capabilities via `setcap` + `sudoers.d`
- Starts both services immediately

---

## Root & Permissions

If you experience "Unknown OS" or cannot run ARP scans:
```bash
bash root-helper.sh
```
This tool verifies your `sudoers.d` and `setcap` configuration.

---

## What's new in v3.1

| Feature | Details |
|---|---|
| **Force Root** | `setcap` + sudoers.d entry — ARP scan never asks for password |
| **Network Name** | SSID shown in header bar and Network Info tab (WiFi + Ethernet) |
| **Full Network Details** | IP, subnet, gateway, DNS, MAC, IPv6, MTU, link speed, signal dBm |
| **Investigate Modal** | Per-device deep dive: ports+services, OS, connections, packets, alerts |
| **Traffic Analysis** | Top talkers TX/RX, protocol breakdown, conversation pairs, anomaly detection |
| **Topology** | Clickable nodes — click any device to open Investigate modal |
| **DPI** | Click any packet row to investigate the source IP |

---

## Ports

| Service | Port |
|---|---|
| Dashboard | 9000 |
| API daemon | 8000 |

---

## Management

```bash
bash start.sh    # restart both services
bash stop.sh     # stop both
bash status.sh   # live health check
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Daemon status, capability flags, SSID |
| GET | `/api/v1/metrics` | CPU, RAM, BW, devices, alerts, packets |
| GET | `/api/v1/network` | Full network details (SSID, IP, gateway, DNS…) |
| GET | `/api/v1/traffic/analysis` | Top talkers, protocols, conversations, anomalies |
| GET | `/api/v1/investigate/{ip}` | Full deep host investigation |
| POST | `/api/v1/scanner/discover` | ARP / ICMP / SYN host scan |
| GET | `/api/v1/scanner/interfaces` | All network interfaces |
| GET | `/api/v1/connections` | Live TCP/UDP socket table |
| GET | `/api/v1/packets?limit=100` | Ring buffer packets |
| POST | `/api/v1/firewall/inject` | iptables DROP / ACCEPT rule |
| GET | `/api/v1/firewall/rules` | Live iptables INPUT chain |
| POST | `/api/v1/sniffer/start` | Start packet capture |
| POST | `/api/v1/sniffer/stop` | Stop packet capture |

---

## AI Copilot

Get a free Gemini API key at https://aistudio.google.com
Enter it via the 🔑 icon in the dashboard header. Stored in your browser only.

The copilot receives your **live** SSID, devices, alerts, and packets on every message.

---

## Docker

```bash
sudo docker compose up -d
# Dashboard: http://localhost:9000
# API:       http://localhost:8000
```

---

## Capability matrix

| Feature | Root | scapy | nmap |
|---|---|---|---|
| Metrics, connections | No | No | No |
| ARP scan | **Yes** | **Yes** | No |
| Packet capture | **Yes** | **Yes** | No |
| Port scan | No | No | **Yes** |
| OS fingerprint | **Yes** | No | **Yes** |
| Firewall injection | **Yes** | No | No |

The installer force-grants root via `setcap` and `sudoers.d` — no manual `sudo` needed after install.
