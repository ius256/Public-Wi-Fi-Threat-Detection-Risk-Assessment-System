"""
PWTDS - Public Wi-Fi Threat Detection & Risk Assessment System
==============================================================

A single-file Flask application. It scans the Wi-Fi network you're connected to
across nine security dimensions and reports, in plain language, whether it's
safe to browse, log in, shop, or bank.

Run it:
    pip install -r requirements.txt
    python app.py            # opens http://127.0.0.1:8765 in your browser

Layout:
    app.py                  <- this file: scanner engine + web server
    templates/index.html    <- the page
    static/style.css        <- styling
    static/app.js           <- browser logic
    validate.py             <- proves the detectors fire (python validate.py)

Everything here is passive and read-only: it inspects your own connection and
your own device. It never attacks a network or scans other people's devices.
"""

from __future__ import annotations

import sys
import os
import re
import json
import time
import ssl
import socket
import platform
import subprocess
import http.client
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, render_template, jsonify, request



# ========================= models =========================

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """
    How much a single finding contributes to risk.

    The numeric value is the "risk weight" of that finding on a 0-100 scale,
    used by the scoring engine. INFO contributes nothing to risk; it is only
    context for the reader.
    """
    INFO = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass
class Finding:
    """A single observation made by one of the scanners."""
    title: str                      # short human headline
    severity: Severity              # how bad it is
    detail: str                     # plain-English explanation for a non-expert
    evidence: str = ""              # the raw fact we observed (kept minimal & non-personal)
    recommendation: str = ""        # what the user / venue can do about it

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "detail": self.detail,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class AccessPoint:
    """One wireless network as seen in a passive scan of broadcast beacons."""
    ssid: str
    bssid: str = ""                 # AP hardware address (MAC)
    security: str = ""              # e.g. "Open", "WEP", "WPA2-PSK", "WPA3"
    signal: Optional[int] = None    # signal strength, % or dBm depending on OS
    channel: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DimensionResult:
    """The outcome of assessing one of the five threat dimensions."""
    key: str                        # machine name, e.g. "encryption"
    name: str                       # display name, e.g. "Encryption Configuration"
    findings: List[Finding] = field(default_factory=list)
    dimension_risk: float = 0.0     # 0 (safe) .. 100 (dangerous), set by scoring
    weight: float = 0.0             # its share of the composite score
    assessed: bool = True           # False if we could not run this check here

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "assessed": self.assessed,
            "dimension_risk": round(self.dimension_risk, 1),
            "weight": self.weight,
            "worst_severity": self.worst_severity.label,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    """The complete result of one assessment run."""
    network_name: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    platform: str = ""
    mode: str = "live"              # "live" or "demo"
    dimensions: List[DimensionResult] = field(default_factory=list)
    overall_risk: float = 0.0       # 0..100 composite
    grade: str = ""                 # A..F
    verdict: str = ""               # one-line plain-English verdict
    access_points: List[AccessPoint] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "PWTDS",
            "network_name": self.network_name,
            "started_at": self.started_at,
            "platform": self.platform,
            "mode": self.mode,
            "overall_risk": round(self.overall_risk, 1),
            "grade": self.grade,
            "verdict": self.verdict,
            "dimensions": [d.to_dict() for d in self.dimensions],
            "access_points": [ap.to_dict() for ap in self.access_points],
        }


# ========================= oui =========================

from typing import Optional

# prefix (first 3 octets, upper, colon-separated) -> vendor
_OUI = {
    "00:1A:2B": "Ayecom", "00:0C:29": "VMware", "00:50:56": "VMware",
    "00:1B:63": "Apple", "3C:15:C2": "Apple", "F0:18:98": "Apple",
    "A4:83:E7": "Apple", "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "00:1D:0F": "TP-Link", "50:C7:BF": "TP-Link",
    "C4:6E:1F": "TP-Link", "AC:84:C6": "TP-Link", "18:A6:F7": "TP-Link",
    "00:14:6C": "Netgear", "20:E5:2A": "Netgear", "A0:40:A0": "Netgear",
    "00:18:E7": "Cameo/Netgear", "00:1F:33": "Netgear", "2C:30:33": "Netgear",
    "00:0F:66": "Cisco-Linksys", "00:25:9C": "Cisco-Linksys", "48:F8:B3": "Cisco-Linksys",
    "00:1C:10": "Cisco-Linksys", "C0:56:27": "Belkin", "94:10:3E": "Belkin",
    "00:26:5A": "D-Link", "1C:AF:F7": "D-Link", "78:54:2E": "D-Link",
    "00:24:01": "D-Link", "34:08:04": "D-Link", "00:1E:58": "WistronNeweb",
    "00:13:46": "D-Link", "F8:1A:67": "TP-Link", "EC:08:6B": "TP-Link",
    "00:0E:8E": "SparkLAN", "00:15:6D": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "78:8A:20": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "00:1D:D8": "Microsoft", "00:17:FA": "Microsoft", "58:82:A8": "Xiaomi",
    "64:09:80": "Xiaomi", "8C:BE:BE": "Xiaomi", "00:9A:CD": "Huawei",
    "00:E0:FC": "Huawei", "48:7B:6B": "Huawei", "70:72:3C": "Huawei",
    "00:16:6F": "Intel", "00:1E:64": "Intel", "34:13:E8": "Intel",
    "3C:A9:F4": "Intel", "00:21:6A": "Intel", "88:53:2E": "Intel",
    "00:03:93": "Apple", "00:05:02": "Apple", "F4:F5:D8": "Google",
    "00:1A:11": "Google", "94:EB:2C": "Google", "AC:22:0B": "Asus",
    "00:1F:C6": "Asus", "50:46:5D": "Asus", "2C:56:DC": "Asus",
    "00:90:4C": "Epigram", "00:26:B0": "Apple", "40:B0:76": "Asus",
}


def normalise_mac(mac: str) -> str:
    """Return an upper-case colon-separated MAC, or '' if it doesn't look valid."""
    if not mac:
        return ""
    hexs = "".join(c for c in mac if c in "0123456789abcdefABCDEF")
    if len(hexs) < 12:
        return ""
    hexs = hexs[:12].upper()
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def vendor(mac: str) -> Optional[str]:
    """Look up the hardware vendor for a MAC, or None if unknown."""
    norm = normalise_mac(mac)
    if not norm:
        return None
    return _OUI.get(norm[:8])


def is_locally_administered(mac: str) -> bool:
    """
    True if the MAC is randomised / locally-administered (the 2nd-least-
    significant bit of the first octet is set). Phones do this for privacy;
    an access point doing it can be a sign of a software-based rogue AP.
    """
    norm = normalise_mac(mac)
    if not norm:
        return False
    try:
        first = int(norm[:2], 16)
    except ValueError:
        return False
    return bool(first & 0b10)


# ========================= history =========================

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _store_path() -> str:
    base = os.path.expanduser("~")
    d = os.path.join(base, ".pwtds")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        d = base
    return os.path.join(d, "history.json")


def _load() -> Dict[str, dict]:
    path = _store_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: Dict[str, dict]) -> None:
    try:
        with open(_store_path(), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


def load_baseline(ssid: str) -> Optional[dict]:
    """Return the stored fingerprint for an SSID, or None if never seen."""
    if not ssid:
        return None
    return _load().get(ssid)


def save_baseline(ssid: str, fingerprint: dict) -> None:
    """Store / update the fingerprint for an SSID."""
    if not ssid:
        return
    data = _load()
    fingerprint = dict(fingerprint)
    fingerprint["last_seen"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if ssid not in data:
        fingerprint["first_seen"] = fingerprint["last_seen"]
    else:
        fingerprint["first_seen"] = data[ssid].get("first_seen", fingerprint["last_seen"])
    data[ssid] = fingerprint
    _save(data)


def diff_baseline(old: dict, new: dict) -> List[dict]:
    """
    Compare an old and new fingerprint; return a list of change descriptors:
    {field, severity, old, new, note}. Severity is a plain string the scanner
    maps to a Finding severity.
    """
    changes: List[dict] = []
    if not old:
        return changes

    # gateway MAC change -> strong signal
    if old.get("gateway_mac") and new.get("gateway_mac") \
            and old["gateway_mac"] != new["gateway_mac"]:
        changes.append({
            "field": "gateway_mac", "severity": "high",
            "old": old["gateway_mac"], "new": new["gateway_mac"],
            "note": "The router's hardware address changed since your last visit. "
                    "That can mean a different (possibly fake) device is now acting "
                    "as the gateway.",
        })

    # security downgrade -> strong signal
    rank = {"open": 0, "wep": 1, "wpa": 2, "wpa2": 3, "wpa3": 4}
    def _rank(s):
        s = (s or "").lower()
        for k in ("wpa3", "wpa2", "wpa", "wep", "open"):
            if k in s:
                return rank[k]
        return -1
    o_sec, n_sec = _rank(old.get("security")), _rank(new.get("security"))
    if o_sec >= 0 and n_sec >= 0 and n_sec < o_sec:
        changes.append({
            "field": "security", "severity": "high",
            "old": old.get("security"), "new": new.get("security"),
            "note": "This network's encryption is weaker than last time. A downgrade "
                    "(e.g. from WPA2 to Open) is a classic look-alike / downgrade sign.",
        })

    # new BSSIDs for a known SSID -> medium
    old_bssids = set(old.get("bssids", []))
    new_bssids = set(new.get("bssids", []))
    added = new_bssids - old_bssids
    if old_bssids and added:
        changes.append({
            "field": "bssids", "severity": "medium",
            "old": sorted(old_bssids), "new": sorted(added),
            "note": "New access-point hardware is broadcasting this network name. "
                    "Often harmless (an added router), but it's how an evil twin "
                    "first appears.",
        })

    # DNS server change -> medium
    old_dns = set(old.get("dns", []))
    new_dns = set(new.get("dns", []))
    if old_dns and new_dns and not (old_dns & new_dns):
        changes.append({
            "field": "dns", "severity": "medium",
            "old": sorted(old_dns), "new": sorted(new_dns),
            "note": "The DNS servers this network hands out changed completely. "
                    "Worth noting, as redirected DNS is a common tampering method.",
        })

    return changes


# ========================= platform_utils =========================

import platform
import re
import subprocess
from typing import Dict, List, Optional, Tuple


OS_NAME = platform.system()  # 'Windows', 'Linux', 'Darwin'


def _run(cmd: List[str], timeout: int = 15) -> str:
    """Run a read-only system command and return stdout, or '' on any failure."""
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return out.stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


# --------------------------------------------------------------------------- #
#  Default gateway (the router we route through)                              #
# --------------------------------------------------------------------------- #
def get_default_gateway() -> Optional[str]:
    """Return the default gateway IP for the active connection, or None."""
    if OS_NAME == "Linux":
        out = _run(["ip", "route", "show", "default"])
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    elif OS_NAME == "Darwin":  # macOS
        out = _run(["route", "-n", "get", "default"])
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    elif OS_NAME == "Windows":
        out = _run(["route", "print", "0.0.0.0"])
        # Rows look like:  0.0.0.0   0.0.0.0   192.168.1.1   192.168.1.23   25
        for line in out.splitlines():
            m = re.search(
                r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", line
            )
            if m:
                return m.group(1)
    return None


# --------------------------------------------------------------------------- #
#  Configured DNS resolvers                                                    #
# --------------------------------------------------------------------------- #
def get_dns_servers() -> List[str]:
    """Return the list of DNS server IPs the system is currently using."""
    servers: List[str] = []
    if OS_NAME in ("Linux", "Darwin"):
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    m = re.match(r"\s*nameserver\s+(\S+)", line)
                    if m:
                        servers.append(m.group(1))
        except OSError:
            pass
        if OS_NAME == "Darwin" and not servers:
            out = _run(["scutil", "--dns"])
            servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", out)
    elif OS_NAME == "Windows":
        out = _run(["ipconfig", "/all"])
        # crude but effective: collect IPs that follow a 'DNS Servers' label block
        capture = False
        for line in out.splitlines():
            if "DNS Servers" in line:
                capture = True
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    servers.append(m.group(1))
                continue
            if capture:
                m = re.match(r"\s+(\d+\.\d+\.\d+\.\d+)\s*$", line)
                if m:
                    servers.append(m.group(1))
                else:
                    capture = False
    # de-duplicate, preserve order
    seen, unique = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


# --------------------------------------------------------------------------- #
#  ARP cache (IP <-> MAC mappings the OS has learned)                         #
# --------------------------------------------------------------------------- #
def get_arp_table() -> List[Tuple[str, str]]:
    """
    Return a list of (ip, mac) pairs from the OS ARP cache.
    Reading the cache is passive - we do not send crafted ARP frames.
    """
    out = _run(["arp", "-a"])
    pairs: List[Tuple[str, str]] = []
    # Matches both  '? (192.168.1.1) at aa:bb:...'  and  '192.168.1.1  aa-bb-...'
    ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    mac_re = re.compile(r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})")
    for line in out.splitlines():
        ip_m = ip_re.search(line)
        mac_m = mac_re.search(line)
        if ip_m and mac_m:
            mac = mac_m.group(1).lower().replace("-", ":")
            pairs.append((ip_m.group(1), mac))
    return pairs


# --------------------------------------------------------------------------- #
#  Currently-connected SSID                                                    #
# --------------------------------------------------------------------------- #
def get_connected_ssid() -> Optional[str]:
    if OS_NAME == "Linux":
        out = _run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"])
        for line in out.splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[1] or None
    elif OS_NAME == "Darwin":
        out = _run(["/System/Library/PrivateFrameworks/Apple80211.framework/"
                    "Versions/Current/Resources/airport", "-I"])
        m = re.search(r"\bSSID:\s*(.+)", out)
        if m:
            return m.group(1).strip()
    elif OS_NAME == "Windows":
        out = _run(["netsh", "wlan", "show", "interfaces"])
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None


# --------------------------------------------------------------------------- #
#  Passive Wi-Fi scan (read broadcast beacons only)                           #
# --------------------------------------------------------------------------- #
def scan_wifi() -> List[AccessPoint]:
    """
    Enumerate nearby access points by reading the beacon frames they already
    broadcast publicly. This is passive: it is the same information your phone
    shows in its Wi-Fi list. Returns [] if no wireless radio / permission.
    """
    if OS_NAME == "Windows":
        return _scan_wifi_windows()
    if OS_NAME == "Linux":
        return _scan_wifi_linux()
    if OS_NAME == "Darwin":
        return _scan_wifi_macos()
    return []


def _scan_wifi_windows() -> List[AccessPoint]:
    out = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    aps: List[AccessPoint] = []
    ssid = ""
    security = ""
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)$", s)
        if m:
            ssid = m.group(1).strip()
            security = ""
            continue
        m = re.match(r"Authentication\s*:\s*(.*)$", s)
        if m:
            security = m.group(1).strip()
            continue
        m = re.match(r"BSSID\s+\d+\s*:\s*(.*)$", s)
        if m:
            aps.append(AccessPoint(ssid=ssid or "<hidden>",
                                   bssid=m.group(1).strip().lower(),
                                   security=security or "Unknown"))
    return aps


def _scan_wifi_linux() -> List[AccessPoint]:
    # nmcli gives a clean, parseable table without root.
    out = _run(["nmcli", "-t", "-f", "SSID,BSSID,SECURITY,SIGNAL,CHAN",
                "device", "wifi", "list"])
    aps: List[AccessPoint] = []
    for line in out.splitlines():
        # nmcli escapes ':' inside BSSID as '\:' - split on unescaped ':'
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace("\\:", ":") for p in parts]
        if len(parts) < 5:
            continue
        ssid, bssid, sec, signal, chan = parts[:5]
        aps.append(AccessPoint(
            ssid=ssid or "<hidden>",
            bssid=bssid.lower(),
            security=(sec or "Open").strip() or "Open",
            signal=int(signal) if signal.isdigit() else None,
            channel=int(chan) if chan.isdigit() else None,
        ))
    return aps


def _scan_wifi_macos() -> List[AccessPoint]:
    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources/airport")
    out = _run([airport, "-s"])
    aps: List[AccessPoint] = []
    for line in out.splitlines()[1:]:  # skip header row
        # SSID BSSID RSSI CHANNEL HT CC SECURITY
        m = re.match(r"\s*(.+?)\s+([0-9a-fA-F:]{17})\s+(-?\d+)\s+(\d+)", line)
        if m:
            security = "Open" if "NONE" in line.upper() else line.split()[-1]
            aps.append(AccessPoint(
                ssid=m.group(1).strip() or "<hidden>",
                bssid=m.group(2).lower(),
                security=security,
                signal=int(m.group(3)),
                channel=int(m.group(4)),
            ))
    return aps


# --------------------------------------------------------------------------- #
#  Network interfaces (used only to spot an active VPN tunnel, read-only).     #
# --------------------------------------------------------------------------- #
def get_network_interfaces() -> List[str]:
    """
    Return a list of network-interface names / adapter descriptions the OS
    currently has. Used purely to check whether a VPN tunnel appears active.
    Best-effort and read-only; returns [] if it cannot tell.
    """
    system = platform.system()
    names: List[str] = []
    try:
        if system == "Windows":
            out = _run(["ipconfig", "/all"])
            for line in out.splitlines():
                s = line.strip()
                # adapter section headers, e.g. "Ethernet adapter Ethernet:"
                if s.lower().endswith(" adapter") or " adapter " in s.lower():
                    names.append(s)
                # description lines name the driver (e.g. WireGuard Tunnel)
                if "description" in s.lower() and ":" in s:
                    names.append(s.split(":", 1)[1].strip())
        elif system == "Darwin":
            out = _run(["ifconfig", "-l"])
            names = out.split()
        else:  # Linux and others
            out = _run(["ip", "-o", "link", "show"])
            if out:
                for line in out.splitlines():
                    # "3: wg0: <..." -> take the token after the index
                    parts = line.split(":")
                    if len(parts) >= 2:
                        names.append(parts[1].strip().split("@")[0])
            else:
                # fall back to sysfs
                import os as _os
                d = "/sys/class/net"
                if _os.path.isdir(d):
                    names = _os.listdir(d)
    except Exception:
        return []
    return [n for n in names if n]


# --------------------------------------------------------------------------- #
#  Listening services on THIS device (read-only, self-directed).              #
#  We only look at our own machine - never at other people's devices.         #
# --------------------------------------------------------------------------- #
_LOOPBACK_PREFIXES = ("127.", "::1", "0.0.0.0.0")  # treat loopback as not-exposed


def get_listening_services() -> List[dict]:
    """
    Return this device's listening TCP/UDP ports that are reachable from the
    network (i.e. bound to 0.0.0.0/:: or a real interface, not just loopback).
    Best-effort, read-only. Returns [] if it can't tell.
    """
    system = platform.system()
    out = ""
    if system == "Windows":
        out = _run(["netstat", "-an"])
    else:
        out = _run(["ss", "-H", "-tuln"]) or _run(["netstat", "-an"])
    if not out:
        raw = _probe_sensitive_listeners()
        return _annotate_reachable(raw)

    services = []
    seen = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        is_listen = ("listen" in low) or (system != "Windows" and "unconn" in low)
        # UDP has no LISTEN state; ss prints UNCONN. netstat udp lines have no state.
        proto = "tcp" if low.startswith("tcp") else ("udp" if low.startswith("udp") else "")
        # find the local address token (host:port or *.port or host.port)
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?|\*)[:.](\d{1,5})\b", line)
        if not m:
            continue
        host, port_s = m.group(1), m.group(2)
        try:
            port = int(port_s)
        except ValueError:
            continue
        if not (is_listen or proto == "udp"):
            continue
        host_norm = host.strip("[]")
        # skip loopback-only bindings (not reachable by others)
        if host_norm.startswith("127.") or host_norm in ("::1",):
            continue
        key = (proto, port)
        if key in seen:
            continue
        seen.add(key)
        services.append({"port": port, "proto": proto or "tcp", "bind": host_norm})

    if not services:
        services = _probe_sensitive_listeners()

    # Tag each service with whether it's actually reachable across the network.
    # A listening port that the firewall blocks is kept but marked unreachable, so
    # the report can say "running but firewall-protected" instead of "exposed".
    return _annotate_reachable(services)


def _windows_firewall_on():
    """On Windows: is the firewall enabled for the active profile? True/False/None."""
    if platform.system() != "Windows":
        return None
    out = _run(["netsh", "advfirewall", "show", "currentprofile"]) or \
          _run(["netsh", "advfirewall", "show", "allprofiles"])
    if not out:
        return None
    m = re.search(r"State\s+(ON|OFF)", out, re.IGNORECASE)
    return (m.group(1).upper() == "ON") if m else None


def _reachable_from_network(port: int, timeout: float = 0.35) -> bool:
    """Try to reach a TCP port on this machine's own network IP. If the firewall
    blocks inbound to it, the connection fails -> it isn't actually exposed."""
    ip = _primary_ip()
    if ip == "127.0.0.1":
        return True  # offline / can't determine — stay conservative
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _annotate_reachable(services: List[dict]) -> List[dict]:
    """Tag each service with 'reachable': can another device on the network
    actually reach it, or is the firewall blocking it? On Windows with the
    firewall on, inbound is blocked by default, so sensitive services are marked
    unreachable (running, but protected)."""
    fw_on = _windows_firewall_on()
    for svc in services:
        port = svc.get("port")
        proto = svc.get("proto", "tcp")
        if port in _SENSITIVE_PORTS:
            if fw_on is True:
                svc["reachable"] = False           # firewall blocks inbound
            elif proto == "tcp":
                svc["reachable"] = _reachable_from_network(port)
            else:
                svc["reachable"] = True             # can't easily test UDP
        else:
            svc["reachable"] = True
    return services


def _primary_ip() -> str:
    """This machine's outbound-interface IP (no packets sent). Falls back to loopback."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def _probe_sensitive_listeners() -> List[dict]:
    """Detect sensitive services listening on this device by trying to reach them
    on the machine's own network IP. Self-directed and read-only."""
    ip = _primary_ip()
    target = ip if ip != "127.0.0.1" else "127.0.0.1"
    found = []
    for port in _SENSITIVE_PORTS:            # defined later; resolved at call time
        try:
            with socket.create_connection((target, port), timeout=0.3):
                found.append({"port": port, "proto": "tcp", "bind": target})
        except OSError:
            continue
    return found


# --------------------------------------------------------------------------- #
#  IPv6 configuration (read-only).                                            #
# --------------------------------------------------------------------------- #
def get_ipv6_info() -> dict:
    """Best-effort IPv6 facts: is there a default IPv6 route / global address?"""
    system = platform.system()
    info = {"has_v6_default": False, "has_global_v6": False}
    try:
        if system == "Windows":
            r = _run(["netsh", "interface", "ipv6", "show", "route"])
            info["has_v6_default"] = "::/0" in r
            a = _run(["netsh", "interface", "ipv6", "show", "address"])
            info["has_global_v6"] = bool(re.search(r"\b2[0-9a-fA-F]{3}:", a))
        elif system == "Darwin":
            r = _run(["netstat", "-rn", "-f", "inet6"])
            info["has_v6_default"] = bool(re.search(r"^default\b", r, re.M))
            info["has_global_v6"] = bool(re.search(r"\b2[0-9a-fA-F]{3}:", r))
        else:
            r = _run(["ip", "-6", "route", "show", "default"])
            info["has_v6_default"] = "default" in r
            a = _run(["ip", "-6", "addr", "show", "scope", "global"])
            info["has_global_v6"] = "inet6" in a
    except Exception:
        pass
    return info


# --------------------------------------------------------------------------- #
#  All default gateways (to spot more than one - a routing anomaly).          #
# --------------------------------------------------------------------------- #
def get_all_gateways() -> List[str]:
    """Best-effort list of IPv4 default gateways. More than one is unusual."""
    system = platform.system()
    gws: List[str] = []
    try:
        if system == "Windows":
            out = _run(["ipconfig"])
            for m in re.finditer(r"Default Gateway.*?:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", out):
                gws.append(m.group(1))
        elif system == "Darwin":
            out = _run(["netstat", "-rn", "-f", "inet"])
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[1]):
                        gws.append(parts[1])
        else:
            out = _run(["ip", "route", "show", "default"])
            for m in re.finditer(r"default via ([0-9]{1,3}(?:\.[0-9]{1,3}){3})", out):
                gws.append(m.group(1))
    except Exception:
        pass
    # de-dup, drop 0.0.0.0
    seen, uniq = set(), []
    for g in gws:
        if g and g != "0.0.0.0" and g not in seen:
            seen.add(g); uniq.append(g)
    return uniq


# ========================= scanners =========================

import json
import http.client
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple



# --------------------------------------------------------------------------- #
#  Shared context: gather OS facts ONCE, then hand them to every scanner.      #
# --------------------------------------------------------------------------- #
@dataclass
class ScanContext:
    connected_ssid: Optional[str] = None
    gateway: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    arp_table: List[Tuple[str, str]] = field(default_factory=list)
    access_points: List[AccessPoint] = field(default_factory=list)
    online_checks: bool = True   # allow DNS / HTTP probes (off => offline/GNS3)
    demo: bool = False           # True when using scripted demo data
    gateway_mac: Optional[str] = None
    listening_services: List[dict] = field(default_factory=list)
    ipv6: dict = field(default_factory=dict)
    all_gateways: List[str] = field(default_factory=list)

    @classmethod
    def gather(cls, online_checks: bool = True) -> "ScanContext":
        """Collect all read-only facts from the live machine."""
        arp = P.get_arp_table()
        gw = P.get_default_gateway()
        gw_mac = None
        for ip, mac in arp:
            if ip == gw:
                gw_mac = mac
                break
        return cls(
            connected_ssid=P.get_connected_ssid(),
            gateway=gw,
            gateway_mac=gw_mac,
            dns_servers=P.get_dns_servers(),
            arp_table=arp,
            access_points=P.scan_wifi(),
            online_checks=online_checks,
            listening_services=P.get_listening_services(),
            ipv6=P.get_ipv6_info(),
            all_gateways=P.get_all_gateways(),
        )


# Common bait names attackers use to lure victims onto an evil twin.
SUSPICIOUS_SSID_HINTS = [
    "free wifi", "free_wifi", "free internet", "public wifi", "guest wifi",
    "wifi free", "free-wifi", "_free", "openwifi", "no password",
]

# Domains that resolve to stable, well-known addresses; used to sanity-check DNS.
DNS_CANARY_DOMAINS = ["one.one.one.one", "dns.google"]

# A random label almost guaranteed NOT to exist. If it resolves to an IP, the
# resolver is fabricating answers (NXDOMAIN hijacking / forced portal).
NXDOMAIN_CANARY = "pwtds-nonexistent-3f9a2c7b1e.example"

# Ground-truth anchors: well-known names whose real addresses are stable and
# publicly documented. Baked in so DNS tampering can be detected using ONLY the
# local resolver - no external service has to be reachable for this to work.
_DNS_ANCHORS = {
    "one.one.one.one": {"1.1.1.1", "1.0.0.1"},
    "dns.google":      {"8.8.8.8", "8.8.4.4"},
}


# --------------------------------------------------------------------------- #
#  1. ENCRYPTION CONFIGURATION                                                 #
# --------------------------------------------------------------------------- #
def _connected_security(ctx: "ScanContext") -> str:
    """Best-effort: the security string of the AP we're connected to."""
    if ctx.connected_ssid:
        for ap in ctx.access_points:
            if ap.ssid == ctx.connected_ssid and ap.security:
                return ap.security
    return ""


def encryption_scanner(ctx: ScanContext) -> DimensionResult:
    """
    Judge the link-layer protection of the network you're on (and the airspace
    around it). Open and WEP networks let anyone nearby read your traffic;
    WPA2/WPA3 do not.
    """
    dim = DimensionResult(key="encryption", name="Encryption Configuration")

    def classify(security: str) -> Tuple[Severity, str]:
        s = (security or "").lower()
        if not s or "open" in s or s == "none" or "--" in s:
            return Severity.CRITICAL, "Open / no encryption"
        if "wep" in s:
            return Severity.CRITICAL, "WEP (broken, trivially decryptable)"
        if "wpa3" in s:
            return Severity.INFO, "WPA3 (current best practice)"
        if "wpa2" in s and "wpa3" in s:
            return Severity.INFO, "WPA2/WPA3 transition mode"
        if "wpa2" in s and s.count("wpa") > 1:
            return Severity.LOW, "WPA/WPA2 mixed mode (legacy fallback)"
        if "wpa2" in s:
            return Severity.INFO, "WPA2 (acceptable)"
        if "wpa" in s:
            return Severity.MEDIUM, "WPA (legacy TKIP)"
        return Severity.MEDIUM, f"Unrecognised scheme ({security})"

    # Assess the network we're actually connected to, if we can identify it.
    target = None
    if ctx.connected_ssid:
        for ap in ctx.access_points:
            if ap.ssid == ctx.connected_ssid:
                target = ap
                break

    if target is not None:
        sev, label = classify(target.security)
        dim.add(Finding(
            title=f"Connected network uses: {label}",
            severity=sev,
            detail=("The network you are connected to protects its traffic with "
                    f"{label}. " + (
                        "This means people nearby cannot read your traffic at the "
                        "link layer." if sev in (Severity.INFO, Severity.LOW) else
                        "This is weak: someone within radio range may be able to "
                        "read or tamper with your traffic.")),
            evidence=f"SSID={target.ssid} security={target.security}",
            recommendation=("Prefer WPA2 or WPA3 networks; avoid entering "
                            "passwords or doing banking on open/WEP networks."),
        ))
        # Hardware vendor context for the AP we're connected to.
        if target.bssid:
            v = oui.vendor(target.bssid)
            if oui.is_locally_administered(target.bssid):
                dim.add(Finding(
                    title="Access point uses a randomised hardware address",
                    severity=Severity.LOW,
                    detail=("The router's MAC looks randomised / software-assigned. "
                            "Phones do this for privacy, but a fixed venue router "
                            "usually shouldn't - worth a second look if unexpected."),
                    evidence=f"BSSID={target.bssid} (locally administered)",
                ))
            elif v:
                dim.add(Finding(
                    title=f"Access-point hardware vendor: {v}",
                    severity=Severity.INFO,
                    detail="Identified from the router's hardware address, for context.",
                    evidence=f"BSSID={target.bssid} -> {v}",
                ))
    elif not ctx.access_points:
        dim.assessed = False
        dim.add(Finding(
            title="No wireless scan available on this machine",
            severity=Severity.INFO,
            detail=("No Wi-Fi radio data was available (e.g. you are on a wired / "
                    "virtual network, or the OS blocked the scan). The encryption "
                    "dimension was skipped. Other dimensions still ran."),
            evidence="scan_wifi() returned no access points",
            recommendation="Run on a wireless client to assess encryption.",
        ))

    # Airspace context: how many open networks are broadcasting nearby?
    open_aps = [ap for ap in ctx.access_points
                if classify(ap.security)[0] == Severity.CRITICAL]
    if open_aps:
        dim.add(Finding(
            title=f"{len(open_aps)} open/WEP network(s) visible nearby",
            severity=Severity.MEDIUM if not target else Severity.LOW,
            detail=("Unprotected networks in the area raise the ambient risk and "
                    "are frequently used to stand up rogue access points."),
            evidence=", ".join(sorted({ap.ssid for ap in open_aps})[:8]),
            recommendation="Treat any open network as publicly readable.",
        ))

    return dim


# --------------------------------------------------------------------------- #
#  2. SSID LEGITIMACY  (rogue AP / evil twin)                                  #
# --------------------------------------------------------------------------- #
def ssid_legitimacy_scanner(ctx: ScanContext) -> DimensionResult:
    """
    An 'evil twin' is a fake AP that copies a real network's name to trick you
    into connecting. Tell-tale signs: the same SSID broadcast from several
    different BSSIDs, especially with mismatched security, and bait names.
    """
    dim = DimensionResult(key="ssid_legitimacy", name="SSID Legitimacy")

    if not ctx.access_points:
        dim.assessed = False
        dim.add(Finding(
            title="No wireless scan available",
            severity=Severity.INFO,
            detail="Evil-twin detection needs a Wi-Fi scan, which was unavailable.",
            recommendation="Run on a wireless client to enable this check.",
        ))
        return dim

    # Group BSSIDs by SSID.
    by_ssid: Dict[str, List[AccessPoint]] = defaultdict(list)
    for ap in ctx.access_points:
        by_ssid[ap.ssid].append(ap)

    for ssid, aps in by_ssid.items():
        bssids = {ap.bssid for ap in aps if ap.bssid}
        sec_set = {ap.security for ap in aps}
        if len(bssids) > 1 and len(sec_set) > 1:
            dim.add(Finding(
                title=f"Possible evil twin: '{ssid}'",
                severity=Severity.HIGH,
                detail=("This network name is broadcast by more than one access "
                        "point WITH DIFFERENT SECURITY SETTINGS. A legitimate "
                        "network normally uses consistent settings; a mismatch is "
                        "a classic evil-twin signature."),
                evidence=f"{len(bssids)} BSSIDs, security seen: {sorted(sec_set)}",
                recommendation=("Do not assume this is the real network. Confirm "
                                "the correct name and password with venue staff."),
            ))
        elif len(bssids) > 2:
            dim.add(Finding(
                title=f"'{ssid}' broadcast from {len(bssids)} radios",
                severity=Severity.LOW,
                detail=("Multiple access points share this name. This is often "
                        "legitimate (mesh / range extenders) but worth noting - a "
                        "rogue AP can hide among genuine ones."),
                evidence=f"BSSIDs={len(bssids)}",
                recommendation="Verify the venue actually runs multiple APs.",
            ))

    # Bait-name heuristic (one finding per SSID, escalated if any instance is open).
    for ssid, aps in by_ssid.items():
        low = ssid.lower()
        if any(h in low for h in SUSPICIOUS_SSID_HINTS):
            is_open = any((ap.security or "").lower() in ("", "open", "--")
                          or "open" in (ap.security or "").lower() for ap in aps)
            sev = Severity.MEDIUM if is_open else Severity.LOW
            dim.add(Finding(
                title=f"Lure-style network name: '{ssid}'",
                severity=sev,
                detail=("Generic 'free wifi' style names are commonly used by "
                        "attackers because people connect to them without thinking."),
                evidence=f"SSID={ssid} security={sorted({ap.security for ap in aps})}",
                recommendation="Only connect to the exact name the venue advertises.",
            ))

    if not dim.findings:
        dim.add(Finding(
            title="No rogue-AP indicators found",
            severity=Severity.INFO,
            detail="No duplicate-name or bait-name patterns were detected in the scan.",
        ))
    return dim


# --------------------------------------------------------------------------- #
#  3. DNS INTEGRITY                                                            #
# --------------------------------------------------------------------------- #
def _resolve_local(host: str) -> List[str]:
    """Resolve a host using the system resolver (whatever the network handed us)."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, OSError):
        return []


# Trusted public resolvers, addressed by IP so we never depend on the local
# (possibly hijacked or DoH-blocking) resolver to *find* them. SNI/Host is the
# resolver's real hostname so the TLS certificate still validates normally.
_DOH_SERVERS = [
    ("1.1.1.1", "cloudflare-dns.com"),
    ("1.0.0.1", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google"),
    ("8.8.4.4", "dns.google"),
]


def _doh_query(ip: str, sni: str, host: str, timeout: int = 6) -> List[str]:
    """One DNS-over-HTTPS lookup to a trusted resolver reached by IP."""
    sslctx = ssl.create_default_context()
    raw = socket.create_connection((ip, 443), timeout=timeout)
    try:
        ss = sslctx.wrap_socket(raw, server_hostname=sni)
    except Exception:
        raw.close()
        raise
    try:
        conn = http.client.HTTPConnection(ip, 443, timeout=timeout)
        conn.sock = ss  # reuse our SNI-correct TLS socket; no re-connect
        path = f"/dns-query?name={urllib.parse.quote(host)}&type=A"
        conn.request("GET", path,
                     headers={"Host": sni, "accept": "application/dns-json"})
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            return []
        data = json.loads(body.decode("utf-8"))
        return sorted({a["data"] for a in data.get("Answer", [])
                       if a.get("type") == 1})
    finally:
        try:
            ss.close()
        except Exception:
            pass


def _resolve_doh(host: str) -> List[str]:
    """
    Resolve a host via DNS-over-HTTPS to a trusted, out-of-band resolver,
    reached by IP so a local attacker can neither tamper with the answer nor
    block us simply by refusing to resolve the resolver's domain name. Tries
    Cloudflare then Google; returns [] only if every trusted resolver is
    unreachable (e.g. the network blocks outbound 443 to them).
    """
    for ip, sni in _DOH_SERVERS:
        try:
            ans = _doh_query(ip, sni, host)
            if ans:
                return ans
        except (ssl.SSLError, OSError, ValueError, TimeoutError,
                http.client.HTTPException):
            continue
    # Last resort: domain-based DoH (works if the IPs are blocked but the name
    # resolves). Not fully out-of-band, but better than no cross-check at all.
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return sorted({a["data"] for a in data.get("Answer", [])
                       if a.get("type") == 1})
    except (urllib.error.URLError, ValueError, OSError, TimeoutError):
        return []


def _encrypted_dns_available() -> bool:
    """True if a well-known DNS-over-TLS resolver (port 853) is reachable."""
    for ip in ("1.1.1.1", "8.8.8.8"):
        try:
            with socket.create_connection((ip, 853), timeout=4):
                return True
        except OSError:
            continue
    return False


def dns_integrity_scanner(ctx: ScanContext) -> DimensionResult:
    """
    Detect DNS redirection: the network silently sending your lookups to the
    wrong place. We compare the local answer against a trusted encrypted answer,
    and we check whether a definitely-nonexistent name is being 'answered'.
    """
    dim = DimensionResult(key="dns_integrity", name="DNS Integrity")

    # Deterministic scripted behaviour for demo / validation scenarios.
    if getattr(ctx, "demo", False):
        if ctx.dns_servers:
            dim.add(Finding(
                title=f"DNS resolver(s): {', '.join(ctx.dns_servers[:4])}",
                severity=Severity.INFO,
                detail="These are the DNS servers the network configured for you.",
                evidence=", ".join(ctx.dns_servers)))
        if getattr(ctx, "dns_hijack", False):
            dim.add(Finding(
                title="Resolver invents answers for non-existent names",
                severity=Severity.HIGH,
                detail=("A domain that should not exist was given an IP address, and "
                        "answers for known domains differ from a trusted resolver. "
                        "This is DNS redirection."),
                evidence=f"{NXDOMAIN_CANARY} -> 172.16.0.1",
                recommendation="Avoid sensitive activity; use a trusted VPN/DoH."))
        else:
            dim.add(Finding(
                title="DNS answers match a trusted resolver",
                severity=Severity.INFO,
                detail="Local DNS results agreed with an out-of-band encrypted resolver."))
        return dim

    if not ctx.online_checks:
        dim.assessed = False
        dim.add(Finding(
            title="DNS probing disabled (offline mode)",
            severity=Severity.INFO,
            detail="Online checks were turned off, so DNS integrity was not tested.",
            recommendation="Re-run with online checks enabled to assess DNS.",
        ))
        return dim

    if ctx.dns_servers:
        dim.add(Finding(
            title=f"DNS resolver(s): {', '.join(ctx.dns_servers[:4])}",
            severity=Severity.INFO,
            detail="These are the DNS servers the network configured for you.",
            evidence=", ".join(ctx.dns_servers),
        ))

    # (a) NXDOMAIN fabrication: does a made-up name resolve to something?
    fabricated = _resolve_local(NXDOMAIN_CANARY)
    if fabricated:
        dim.add(Finding(
            title="Resolver invents answers for non-existent names",
            severity=Severity.HIGH,
            detail=("A domain that should not exist was given an IP address. This "
                    "means the network is intercepting DNS - used for forced "
                    "portals, ad injection, or redirecting you to fake sites."),
            evidence=f"{NXDOMAIN_CANARY} -> {', '.join(fabricated)}",
            recommendation=("Avoid sensitive activity. Consider a trusted VPN or "
                            "DNS-over-HTTPS so lookups can't be tampered with."),
        ))

    # (b) Ground-truth anchors: compare the local resolver's answers for a few
    # well-known names against their real, published addresses. Needs only the
    # local resolver, so it works on any network - even one that blocks DoH.
    anchor_checked = 0
    anchor_bad = 0
    for host, known in _DNS_ANCHORS.items():
        got = set(_resolve_local(host))
        if not got:
            continue
        anchor_checked += 1
        if got.isdisjoint(known):
            anchor_bad += 1
            dim.add(Finding(
                title=f"DNS answer for {host} doesn't match its real address",
                severity=Severity.HIGH,
                detail=("A well-known site resolved to an unexpected address. That "
                        "is a strong sign the network is redirecting your web "
                        "lookups somewhere it controls."),
                evidence=f"{host} -> {sorted(got)}  (expected {sorted(known)})",
                recommendation="Don't log in or pay here; you may be redirected.",
            ))

    # (c) Bonus: out-of-band DoH cross-check when a trusted resolver is reachable.
    doh_ok = 0
    doh_bad = 0
    for host in _DNS_ANCHORS:
        trusted = _resolve_doh(host)
        if not trusted:
            continue
        local = set(_resolve_local(host))
        if not local:
            continue
        doh_ok += 1
        if local.isdisjoint(set(trusted)):
            doh_bad += 1
            dim.add(Finding(
                title=f"DNS answer for {host} differs from a trusted resolver",
                severity=Severity.HIGH,
                detail=("The local network's answer doesn't overlap with what a "
                        "trusted encrypted resolver returned - a strong indicator "
                        "of DNS redirection."),
                evidence=f"local={sorted(local)} trusted={sorted(trusted)}",
                recommendation="Do not log in to anything; the network may be MITM.",
            ))

    if not (fabricated or anchor_bad or doh_bad):
        if anchor_checked or doh_ok:
            dim.add(Finding(
                title="DNS answers look correct",
                severity=Severity.INFO,
                detail=("Well-known sites resolved to their real, published "
                        "addresses and made-up names were correctly rejected - no "
                        "sign of DNS redirection on this network."),
                evidence=(f"verified {max(anchor_checked, doh_ok)} known domain(s)"
                          + (" incl. encrypted cross-check" if doh_ok else "")),
            ))
        else:
            # Couldn't resolve even the anchor names -> genuinely unknown, not safe.
            dim.assessed = False
            dim.add(Finding(
                title="DNS could not be checked here",
                severity=Severity.INFO,
                detail=("No name lookups succeeded, so DNS couldn't be assessed "
                        "(you may be behind a login page, or offline)."),
            ))

    # Encrypted-DNS availability (context: can you escape a tampering resolver?)
    if _encrypted_dns_available():
        dim.add(Finding(
            title="Encrypted DNS is available",
            severity=Severity.INFO,
            detail="A trusted encrypted-DNS service is reachable, so you can use "
                   "DNS-over-HTTPS/TLS to stop this network tampering with lookups.",
            evidence="DoT reachable on port 853",
        ))
    else:
        dim.add(Finding(
            title="Encrypted DNS appears blocked",
            severity=Severity.LOW,
            detail="This network blocks the usual encrypted-DNS services. That is "
                   "sometimes just a strict firewall, but it also prevents you from "
                   "bypassing DNS tampering, so treat lookups with extra care.",
            recommendation="Prefer a VPN, which tunnels DNS as well.",
        ))
    return dim


# --------------------------------------------------------------------------- #
#  4. ARP BEHAVIOUR                                                            #
# --------------------------------------------------------------------------- #
def arp_behaviour_scanner(ctx: ScanContext) -> DimensionResult:
    """
    ARP spoofing lets an attacker put themselves between you and the router.
    The classic footprint in the ARP cache is ONE MAC address claiming SEVERAL
    IP addresses (the attacker pretending to be the gateway *and* others).
    Reading the cache is passive.
    """
    dim = DimensionResult(key="arp_behaviour", name="ARP Behaviour")

    if not ctx.arp_table:
        dim.assessed = False
        dim.add(Finding(
            title="ARP cache empty or unavailable",
            severity=Severity.INFO,
            detail="No ARP entries were readable, so this check was skipped.",
            recommendation="Generate some traffic (open a page) then re-run.",
        ))
        return dim

    # Map MAC -> set of IPs it claims.
    mac_to_ips: Dict[str, set] = defaultdict(set)
    for ip, mac in ctx.arp_table:
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        mac_to_ips[mac].add(ip)

    flagged = False
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            flagged = True
            sev = Severity.CRITICAL if ctx.gateway in ips else Severity.HIGH
            dim.add(Finding(
                title="One hardware address is claiming multiple IPs",
                severity=sev,
                detail=("A single device is answering for several IP addresses on "
                        "this network. That is the signature of an ARP-spoofing "
                        "man-in-the-middle attack" + (
                            " - and it includes the gateway IP, meaning your router "
                            "may be impersonated." if ctx.gateway in ips else ".")),
                evidence=f"MAC {mac} -> IPs {sorted(ips)}",
                recommendation=("Disconnect and avoid sensitive activity. On a real "
                                "network this warrants reporting to the venue."),
            ))

    # Note the gateway MAC for transparency.
    if ctx.gateway:
        gw_macs = [m for m, ips in mac_to_ips.items() if ctx.gateway in ips]
        if gw_macs:
            dim.add(Finding(
                title=f"Gateway {ctx.gateway} is at {gw_macs[0]}",
                severity=Severity.INFO,
                detail="Recorded the gateway's hardware address for reference.",
                evidence=f"gateway={ctx.gateway} mac={gw_macs[0]}",
            ))

    if not flagged:
        dim.add(Finding(
            title="No ARP-spoofing indicators found",
            severity=Severity.INFO,
            detail="Every hardware address in the cache maps to a single IP.",
        ))

    # Routing anomaly: more than one default gateway is unusual on a normal LAN.
    if len(getattr(ctx, "all_gateways", []) or []) > 1:
        dim.add(Finding(
            title="More than one default gateway is present",
            severity=Severity.MEDIUM,
            detail=("Your device has multiple default routes. That can be normal "
                    "with a VPN, but it can also mean traffic is being steered "
                    "through an unexpected device."),
            evidence=f"gateways: {', '.join(ctx.all_gateways)}",
            recommendation="If you didn't set up a second route/VPN, be cautious.",
        ))

    # IPv6 context: a v6 default route means controls applied only to IPv4 could
    # be bypassed. Informational, since v6 is normal on many networks.
    ipv6 = getattr(ctx, "ipv6", {}) or {}
    if ipv6.get("has_v6_default"):
        dim.add(Finding(
            title="IPv6 is active on this network",
            severity=Severity.INFO,
            detail=("This network provides IPv6. That's normal, but worth noting: "
                    "protections that only cover IPv4 wouldn't apply to IPv6 traffic."),
            evidence="IPv6 default route present",
        ))
    return dim


# --------------------------------------------------------------------------- #
#  5. CAPTIVE PORTAL & TRANSPORT SECURITY                                      #
# --------------------------------------------------------------------------- #
def _http_probe(url: str, timeout: int = 8):
    """Return (status, final_url, body_snippet) or None. No redirects followed
    automatically so we can *see* the redirect."""
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(url, timeout=timeout)
        body = resp.read(512).decode("utf-8", "ignore")
        return resp.status, resp.geturl(), body
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "") if e.headers else ""
        return e.code, loc, ""
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def captive_portal_scanner(ctx: ScanContext) -> DimensionResult:
    """
    Many venue networks show a login/terms page (a captive portal) before they
    let you online. We check (a) whether one is present, (b) whether it and the
    network as a whole preserve HTTPS - so credentials can't be stripped.
    """
    dim = DimensionResult(key="captive_portal", name="Captive Portal Security")

    # Deterministic scripted behaviour for demo / validation scenarios.
    if getattr(ctx, "demo", False):
        if getattr(ctx, "portal_http", False):
            dim.add(Finding(
                title="Captive portal detected",
                severity=Severity.MEDIUM,
                detail=("You are redirected to a login portal served over PLAIN "
                        "HTTP, so anything typed into it can be read by others "
                        "on the network."),
                evidence="redirect -> http://portal.local/login",
                recommendation="Never reuse a real password on a non-HTTPS portal."))
        else:
            dim.add(Finding(
                title="No captive portal (open internet)",
                severity=Severity.INFO,
                detail="The network returned direct internet access with no portal."))
        if getattr(ctx, "tls_bad", False):
            dim.add(Finding(
                title="TLS certificate failed to validate",
                severity=Severity.HIGH,
                detail=("A secure connection to a well-known site presented an "
                        "invalid certificate - a sign of HTTPS interception."),
                recommendation="Do not click through certificate warnings here."))
        else:
            dim.add(Finding(
                title="HTTPS certificate validates correctly",
                severity=Severity.INFO,
                detail="A trusted HTTPS connection succeeded with a valid certificate."))
        return dim

    if not ctx.online_checks:
        dim.assessed = False
        dim.add(Finding(
            title="Portal probing disabled (offline mode)",
            severity=Severity.INFO,
            detail="Online checks were off, so the captive-portal check was skipped.",
        ))
        return dim

    # Standard 'no content' connectivity endpoint; a real internet returns 204.
    probe = _http_probe("http://connectivitycheck.gstatic.com/generate_204")
    if probe is None:
        dim.add(Finding(
            title="Connectivity check could not complete",
            severity=Severity.LOW,
            detail="Could not reach the internet to test for a captive portal.",
            recommendation="If a login page is expected, complete it then re-run.",
        ))
    else:
        status, final_url, _ = probe
        if status == 204:
            dim.add(Finding(
                title="No captive portal (open internet)",
                severity=Severity.INFO,
                detail="The network returned direct internet access with no portal.",
            ))
        elif status in (301, 302, 303, 307, 308) or (status == 200):
            portal_https = final_url.startswith("https://")
            dim.add(Finding(
                title="Captive portal detected",
                severity=Severity.LOW if portal_https else Severity.MEDIUM,
                detail=("You are redirected to a portal before reaching the "
                        "internet. " + ("It is served over HTTPS." if portal_https
                        else "It is served over PLAIN HTTP, so anything you type "
                             "into it (including any password) can be read by "
                             "others on the network.")),
                evidence=f"redirect -> {final_url or '(unknown)'}",
                recommendation=("Never reuse a real password on a portal; if it "
                                "isn't HTTPS, don't enter anything sensitive."),
            ))

    # Transport check: can we complete a valid TLS handshake to a known host?
    try:
        ctx_ssl = ssl.create_default_context()
        with socket.create_connection(("www.cloudflare.com", 443), timeout=8) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname="www.cloudflare.com") as ss:
                cert = ss.getpeercert()
        if cert:
            dim.add(Finding(
                title="HTTPS certificate validates correctly",
                severity=Severity.INFO,
                detail=("A trusted HTTPS connection succeeded with a valid "
                        "certificate - no evidence of TLS interception on this host."),
            ))
    except ssl.SSLError:
        dim.add(Finding(
            title="TLS certificate failed to validate",
            severity=Severity.HIGH,
            detail=("The secure connection to a well-known site presented an "
                    "invalid certificate. This can indicate HTTPS interception "
                    "(a machine-in-the-middle trying to read encrypted traffic)."),
            recommendation="Do not click through certificate warnings on this network.",
        ))
    except (socket.timeout, OSError, TimeoutError):
        pass  # no internet yet (e.g. pre-portal) - not scored

    return dim


# --------------------------------------------------------------------------- #
#  6. TRANSPORT SECURITY  (are your padlock / HTTPS connections really private?)#
# --------------------------------------------------------------------------- #
# A few globally-reachable HTTPS hosts. We validate their certificates: if a
# well-known site suddenly presents an untrusted certificate, something on the
# path is trying to read inside your encrypted traffic. This is the single most
# important check for whether logging in / paying is safe.
_TLS_HOSTS = ["www.cloudflare.com", "www.google.com", "www.wikipedia.org"]


def _tls_probe(host: str, port: int = 443, timeout: int = 7):
    """Return 'ok', 'intercepted', or 'unreachable' for a strict TLS handshake."""
    try:
        sslctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with sslctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.getpeercert()
        return "ok"
    except ssl.SSLCertVerificationError:
        return "intercepted"
    except ssl.SSLError:
        return "intercepted"
    except (socket.timeout, OSError, TimeoutError, ValueError):
        return "unreachable"


def transport_security_scanner(ctx: ScanContext) -> DimensionResult:
    """
    Check that your encrypted connections (the ones with the padlock, used by
    banks, email and shops) reach their real destinations without being opened
    up in transit.
    """
    dim = DimensionResult(key="transport_security", name="Private Connections (HTTPS)")

    if getattr(ctx, "demo", False):
        if getattr(ctx, "tls_bad", False):
            dim.add(Finding(
                title="Someone may be reading your secure connections",
                severity=Severity.HIGH,
                detail=("A padlocked (HTTPS) connection to a well-known site was "
                        "met with a fake security certificate. That is what it "
                        "looks like when a network tries to see inside your "
                        "encrypted traffic - the exact thing that puts passwords "
                        "and card numbers at risk."),
                evidence="certificate verification failed for a trusted site",
                recommendation="Do not log in or pay on this network. Use mobile data."))
        else:
            dim.add(Finding(
                title="Your secure connections are private",
                severity=Severity.INFO,
                detail=("Padlocked (HTTPS) connections to trusted sites checked out "
                        "with valid certificates - no sign of anyone reading inside "
                        "your encrypted traffic."),
                evidence="certificates validated on trusted sites"))
        return dim

    if not ctx.online_checks:
        dim.assessed = False
        dim.add(Finding(
            title="Secure-connection check needs the internet",
            severity=Severity.INFO,
            detail="Online checks were off, so HTTPS integrity was not tested.",
            recommendation="Turn off Offline mode to check this."))
        return dim

    results = [(_h, _tls_probe(_h)) for _h in _TLS_HOSTS]
    intercepted = [h for h, r in results if r == "intercepted"]
    ok = [h for h, r in results if r == "ok"]

    if intercepted:
        dim.add(Finding(
            title="Someone may be reading your secure connections",
            severity=Severity.HIGH,
            detail=("A padlocked (HTTPS) connection to a well-known site was met "
                    "with an untrusted security certificate. That can mean the "
                    "network is trying to look inside your encrypted traffic - "
                    "the very thing that protects passwords and payments."),
            evidence=f"certificate check failed for: {', '.join(intercepted)}",
            recommendation=("Do not enter passwords or card details here. If your "
                            "browser shows a certificate warning, never click "
                            "through it. Use mobile data for anything sensitive."),
        ))
    elif ok:
        dim.add(Finding(
            title="Your secure connections are private",
            severity=Severity.INFO,
            detail=("Padlocked (HTTPS) connections to trusted sites succeeded with "
                    "valid certificates. There is no sign that this network is "
                    "reading inside your encrypted traffic."),
            evidence=f"certificates validated on: {', '.join(ok)}",
        ))
    else:
        dim.add(Finding(
            title="Could not confirm your secure connections",
            severity=Severity.LOW,
            detail=("We could not reach trusted sites to test HTTPS (you may be "
                    "behind a login page, or have no internet yet). Treat secure "
                    "connections as unverified until you can re-check."),
            recommendation="Finish any login page, then run the check again.",
        ))
    return dim


# --------------------------------------------------------------------------- #
#  7. VPN PROTECTION  (are you shielded no matter what the network does?)       #
# --------------------------------------------------------------------------- #
_VPN_HINTS = ("tun", "tap", "wg", "ppp", "vpn", "wireguard", "wintun", "nordlynx",
              "proton", "tailscale", "zerotier", "openvpn", "utun")


def vpn_presence_scanner(ctx: ScanContext) -> DimensionResult:
    """
    Note whether a VPN appears to be active. A VPN encrypts everything you send,
    so even an unsafe network can't read it - this is the strongest single thing
    a user can do for their own safety, so we surface it clearly. Informational
    only: it never adds risk, it only reassures or gently suggests.
    """
    dim = DimensionResult(key="vpn_presence", name="VPN Protection")

    if getattr(ctx, "demo", False):
        active = getattr(ctx, "vpn", False)
    else:
        names = " ".join(P.get_network_interfaces()).lower()
        # Require a fairly specific tunnel hint to avoid false "you're protected".
        strong = ("wg", "wireguard", "wintun", "nordlynx", "proton", "tailscale",
                  "zerotier", "openvpn", "vpn", "ppp", "tun0", "tun1", "tap")
        active = any(h in names for h in strong)

    if active:
        dim.add(Finding(
            title="A VPN appears to be active",
            severity=Severity.INFO,
            detail=("Your traffic looks like it is going through a VPN tunnel, "
                    "which encrypts everything you send. Even on an open or "
                    "untrusted network, that keeps your logins and payments "
                    "private from people nearby."),
            evidence="a VPN-style network adapter is present",
        ))
    else:
        dim.add(Finding(
            title="No VPN detected",
            severity=Severity.INFO,
            detail=("You don't appear to be using a VPN. On public Wi-Fi, turning "
                    "one on is the easiest way to protect everything you do - it "
                    "encrypts your traffic so the network can't read it."),
            recommendation="Consider a reputable VPN before sensitive activity here.",
        ))
    return dim


# --------------------------------------------------------------------------- #
#  8. DEVICE EXPOSURE  (what YOUR OWN device is offering to this network)       #
# --------------------------------------------------------------------------- #
# On public Wi-Fi, services your device leaves listening can be reached by other
# people on the same network. This is the ethical, self-directed counterpart to
# "network isolation": we inspect only our own machine, never other people's.
_SENSITIVE_PORTS = {
    445:  ("Windows file sharing (SMB)", Severity.HIGH),
    139:  ("NetBIOS file sharing", Severity.HIGH),
    137:  ("NetBIOS name service", Severity.MEDIUM),
    3389: ("Remote Desktop (RDP)", Severity.HIGH),
    23:   ("Telnet (unencrypted remote login)", Severity.HIGH),
    21:   ("FTP (often unencrypted)", Severity.MEDIUM),
    22:   ("SSH remote login", Severity.MEDIUM),
    5900: ("VNC remote screen", Severity.HIGH),
    5353: ("mDNS / Bonjour discovery", Severity.LOW),
    631:  ("Printer sharing (IPP/CUPS)", Severity.LOW),
    8080: ("Development / proxy web server", Severity.MEDIUM),
    3000: ("Development web server", Severity.MEDIUM),
    5000: ("Development web server", Severity.MEDIUM),
    8000: ("Development web server", Severity.LOW),
    9200: ("Elasticsearch", Severity.HIGH),
    27017:("MongoDB", Severity.HIGH),
    3306: ("MySQL database", Severity.HIGH),
    5432: ("PostgreSQL database", Severity.HIGH),
}


def device_exposure_scanner(ctx: ScanContext) -> DimensionResult:
    """
    Flag services on THIS device that are reachable from the network, which on
    public Wi-Fi means other people nearby could try to reach them.
    """
    dim = DimensionResult(key="device_exposure", name="Your Device's Exposure")

    if getattr(ctx, "demo", False):
        exposed = getattr(ctx, "demo_exposed", [])
        if not exposed:
            dim.add(Finding(
                title="Your device isn't exposing risky services",
                severity=Severity.INFO,
                detail="No sensitive shared services were found listening on the "
                       "network side of your device."))
            return dim
        for port in exposed:
            label, sev = _SENSITIVE_PORTS.get(port, (f"service on port {port}", Severity.MEDIUM))
            dim.add(Finding(title=f"Exposed: {label}", severity=sev,
                            detail="Reachable by others on this network.",
                            evidence=f"tcp/{port} listening"))
        return dim

    services = ctx.listening_services or []
    sensitive = [s for s in services if s.get("port") in _SENSITIVE_PORTS]
    reachable = [s for s in sensitive if s.get("reachable", True)]
    blocked   = [s for s in sensitive if not s.get("reachable", True)]

    if not sensitive:
        fw_on = _windows_firewall_on()
        if fw_on is True:
            dim.add(Finding(
                title="Your device isn't reachable — firewall is protecting you",
                severity=Severity.INFO,
                detail="Your firewall is on and blocking incoming connections, so "
                       "others on this network can't reach services on your device. "
                       "This is exactly what you want.",
                evidence="firewall enabled for the active network profile"))
        else:
            dim.add(Finding(
                title="No exposed services detected",
                severity=Severity.INFO,
                detail="No sensitive services are reachable from the network on "
                       "your device."))
        return dim

    if reachable:
        for svc in reachable:
            label, sev = _SENSITIVE_PORTS[svc["port"]]
            dim.add(Finding(
                title=f"Your device is exposing: {label}",
                severity=sev,
                detail=("This service is reachable by others on the same Wi-Fi. "
                        "Fine on your home network, risky on public Wi-Fi."),
                evidence=f"{svc.get('proto','tcp')}/{svc['port']} reachable at "
                         f"{svc.get('bind','*')}",
                recommendation=("Turn on your firewall (or set this network to "
                                "Public), or stop the service while on public Wi-Fi.")))
        if blocked:
            names = ", ".join(sorted({_SENSITIVE_PORTS[s["port"]][0] for s in blocked}))
            dim.add(Finding(
                title="Other services are running but firewall-blocked",
                severity=Severity.INFO,
                detail=f"These are listening but currently protected: {names}."))
    else:
        # Sensitive services are running, but the firewall is blocking them — so
        # they're NOT exposed. Show them transparently, at no risk.
        names = ", ".join(sorted({_SENSITIVE_PORTS[s["port"]][0] for s in blocked}))
        dim.add(Finding(
            title="Services are running, but your firewall is blocking them",
            severity=Severity.INFO,
            detail=(f"Your device is running {names}, but your firewall is stopping "
                    "anyone on this network from reaching them — so they are not "
                    "exposed. If you turned the firewall off, they would become "
                    "reachable."),
            evidence="listening but not reachable from the network"))
    return dim


# --------------------------------------------------------------------------- #
#  9. NETWORK HISTORY  (has this network changed since you last used it?)       #
# --------------------------------------------------------------------------- #
def network_history_scanner(ctx: ScanContext) -> DimensionResult:
    """
    Compare this network against a remembered baseline and flag meaningful
    changes (gateway MAC, security downgrade, new BSSIDs, changed DNS). First
    visit records a baseline. Informational-to-serious depending on the change.
    """
    dim = DimensionResult(key="network_history", name="Network History")

    if getattr(ctx, "demo", False):
        if getattr(ctx, "demo_history_change", False):
            dim.add(Finding(
                title="This network changed since last time",
                severity=Severity.HIGH,
                detail="The router's hardware address is different from the baseline "
                       "recorded on a previous visit - a strong look-alike signal.",
                evidence="gateway MAC differs from stored baseline",
                recommendation="Treat as untrusted until you've confirmed it's genuine."))
        else:
            dim.add(Finding(
                title="Matches its known baseline",
                severity=Severity.INFO,
                detail="This network looks the same as the last time it was seen."))
        return dim

    ssid = ctx.connected_ssid
    if not ssid:
        dim.assessed = False
        dim.add(Finding(
            title="No network name to track history for",
            severity=Severity.INFO,
            detail="Not connected to a named Wi-Fi network, so history can't apply."))
        return dim

    fingerprint = {
        "security": _connected_security(ctx),
        "gateway_mac": ctx.gateway_mac,
        "gateway_ip": ctx.gateway,
        "bssids": sorted({ap.bssid for ap in ctx.access_points
                          if ap.ssid == ssid and ap.bssid}),
        "dns": list(ctx.dns_servers or []),
    }

    baseline = history.load_baseline(ssid)
    if baseline is None:
        dim.add(Finding(
            title="First visit - baseline recorded",
            severity=Severity.INFO,
            detail=("This is the first time PWTDS has seen this network, so it saved "
                    "a fingerprint. Next time, it can tell you if anything changed."),
            evidence=f"stored: security={fingerprint['security']}, "
                     f"gateway_mac={fingerprint['gateway_mac'] or 'n/a'}",
        ))
    else:
        changes = history.diff_baseline(baseline, fingerprint)
        if not changes:
            dim.add(Finding(
                title="Matches its known baseline",
                severity=Severity.INFO,
                detail="This network looks the same as the last time you used it - "
                       "same router, encryption and DNS.",
                evidence=f"last seen {baseline.get('last_seen','?')}",
            ))
        else:
            sev_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
            for ch in changes:
                dim.add(Finding(
                    title=f"Changed since last visit: {ch['field']}",
                    severity=sev_map.get(ch["severity"], Severity.LOW),
                    detail=ch["note"],
                    evidence=f"was {ch['old']} -> now {ch['new']}",
                    recommendation="Confirm the network is genuine before trusting it.",
                ))

    # persist the latest fingerprint for next time (never in demo mode)
    history.save_baseline(ssid, fingerprint)
    return dim


# --------------------------------------------------------------------------- #
#  Registry: the canonical order + default weights of the dimensions.          #
# --------------------------------------------------------------------------- #
SCANNERS = [
    encryption_scanner,
    ssid_legitimacy_scanner,
    dns_integrity_scanner,
    arp_behaviour_scanner,
    transport_security_scanner,
    captive_portal_scanner,
    device_exposure_scanner,
    network_history_scanner,
    vpn_presence_scanner,
]


# ========================= scoring =========================

from typing import Dict, List


# Default weights - how much each dimension counts toward the final score.
# Rationale: encryption and evil-twin and DNS carry the highest real-world
# impact for a public-Wi-Fi user, so they dominate. Must sum to 1.0.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "encryption":         0.18,
    "ssid_legitimacy":    0.15,
    "dns_integrity":      0.15,
    "transport_security": 0.16,
    "arp_behaviour":      0.12,
    "captive_portal":     0.08,
    "device_exposure":    0.10,
    "network_history":    0.06,
    "vpn_presence":       0.00,   # informational only — never adds risk
}


def score_dimension(dim: DimensionResult) -> float:
    """Collapse a dimension's findings into a single 0-100 risk value."""
    risk_findings = [f for f in dim.findings if f.severity is not Severity.INFO]
    if not risk_findings:
        return 0.0
    values = sorted((f.severity.value for f in risk_findings), reverse=True)
    base = values[0]                       # worst finding sets the floor
    # Each additional non-info finding adds a diminishing amount of risk.
    bonus = sum(v * (0.15 / (i + 1)) for i, v in enumerate(values[1:]))
    return min(100.0, base + bonus)


def grade_for(risk: float) -> str:
    if risk < 10:
        return "A"
    if risk < 30:
        return "B"
    if risk < 50:
        return "C"
    if risk < 70:
        return "D"
    return "F"


def verdict_for(risk: float) -> str:
    if risk < 10:
        return "Low risk - safe for normal use, including logins over HTTPS."
    if risk < 30:
        return "Mostly safe - fine for browsing; stay on HTTPS for sensitive tasks."
    if risk < 50:
        return "Use with caution - avoid banking or entering important passwords."
    if risk < 70:
        return "High risk - do not perform any sensitive activity on this network."
    return "Dangerous - disconnect; strong indicators of active interception."


def compute(result: ScanResult,
            weights: Dict[str, float] | None = None) -> ScanResult:
    """Fill in dimension_risk, weight, overall_risk, grade and verdict."""
    weights = weights or DEFAULT_WEIGHTS

    # Score each dimension and attach its configured weight.
    for dim in result.dimensions:
        dim.dimension_risk = score_dimension(dim)
        dim.weight = weights.get(dim.key, 0.0)

    # Re-normalise weights across only the dimensions we could actually assess.
    assessed = [d for d in result.dimensions if d.assessed]
    total_w = sum(d.weight for d in assessed)
    if total_w > 0:
        weighted = sum(d.dimension_risk * (d.weight / total_w) for d in assessed)
    else:
        weighted = 0.0

    # A network is only as safe as its weakest dimension: an evil twin or an
    # active man-in-the-middle is dangerous even if everything else is clean.
    # So we blend the weighted average with the single worst dimension rather
    # than letting clean dimensions dilute one severe problem. This tracks
    # expert judgement far better than a pure average.
    worst = max((d.dimension_risk for d in assessed), default=0.0)
    overall = 0.6 * weighted + 0.4 * worst

    result.overall_risk = round(overall, 1)
    result.grade = grade_for(result.overall_risk)
    result.verdict = verdict_for(result.overall_risk)
    return result


# ========================= advice =========================

from typing import Dict, List


_SEV_ORDER = {s.label: s.value for s in Severity}


def _dim(result: ScanResult, key: str):
    for d in result.dimensions:
        if d.key == key:
            return d
    return None


def _worst(result: ScanResult, key: str) -> int:
    d = _dim(result, key)
    if not d or not d.assessed:
        return -1  # unknown / not assessed
    return d.worst_severity.value


def _flags(result: ScanResult) -> Dict[str, bool]:
    enc = _worst(result, "encryption")
    return {
        # link to the router is unencrypted (open / WEP) on the network we're on
        "open_wifi":     enc == Severity.CRITICAL.value,
        "link_secure":   enc not in (Severity.CRITICAL.value, -1),
        "evil_twin":     _worst(result, "ssid_legitimacy") >= Severity.HIGH.value,
        "dns_bad":       _worst(result, "dns_integrity") >= Severity.HIGH.value,
        "mitm":          _worst(result, "arp_behaviour") >= Severity.HIGH.value,
        "intercepted":   _worst(result, "transport_security") >= Severity.HIGH.value,
        "transport_ok":  _worst(result, "transport_security") in
                         (Severity.INFO.value,),
        "transport_unknown": _worst(result, "transport_security") in
                             (-1, Severity.LOW.value),
        "portal_http":   (_dim(result, "captive_portal") is not None and
                          any("HTTP" in f.evidence.upper() or "PLAIN HTTP" in f.detail.upper()
                              for f in _dim(result, "captive_portal").findings
                              if f.severity.value >= Severity.MEDIUM.value)),
        "vpn_on":        (_dim(result, "vpn_presence") is not None and
                          any(f.title.lower().startswith("a vpn")
                              for f in _dim(result, "vpn_presence").findings)),
        "exposed":       _worst(result, "device_exposure") >= Severity.HIGH.value,
        "hist_changed":  _worst(result, "network_history") >= Severity.HIGH.value,
    }


def _task(level: str, reason: str) -> Dict[str, str]:
    return {"level": level, "reason": reason}


def _tasks(f: Dict[str, bool]) -> List[Dict[str, str]]:
    active_attack = f["intercepted"] or f["mitm"] or f["dns_bad"] or f["evil_twin"]

    # --- General browsing ---------------------------------------------------
    if f["intercepted"] or f["mitm"] or f["dns_bad"]:
        browse = _task("avoid", "This network shows signs of tampering, so even "
                                "normal browsing isn't trustworthy right now.")
    elif f["evil_twin"]:
        browse = _task("careful", "There may be a fake copy of this network nearby. "
                                  "Make sure you're on the real one.")
    else:
        browse = _task("safe", "Reading websites and watching videos is fine here.")

    # --- Logging in (email, social) ----------------------------------------
    if active_attack:
        login = _task("avoid", "Signs of interception mean your password could be "
                               "captured. Don't log in here.")
    elif f["vpn_on"]:
        login = _task("safe", "Your VPN encrypts everything, so logging in is "
                              "protected even on this network.")
    elif f["open_wifi"]:
        login = _task("careful", "The Wi-Fi is open. Only log in on sites showing "
                                 "the padlock, or turn on a VPN first.")
    elif f["transport_unknown"]:
        login = _task("careful", "We couldn't fully confirm secure connections. "
                                 "Stick to sites with the padlock.")
    else:
        login = _task("safe", "Secure connections checked out. Logging in over "
                              "HTTPS (the padlock) is fine.")

    # --- Shopping / entering card details ----------------------------------
    if active_attack:
        shop = _task("avoid", "Don't enter card details - this network may be "
                              "intercepting traffic.")
    elif f["vpn_on"] and not f["transport_unknown"]:
        shop = _task("safe", "With your VPN on and secure connections intact, "
                             "paying is protected.")
    elif f["open_wifi"] or f["transport_unknown"]:
        shop = _task("careful", "Prefer mobile data or a VPN before typing card "
                                "details on this network.")
    else:
        shop = _task("safe", "Secure connections are intact. Paying on sites with "
                             "the padlock should be fine.")

    # --- Online banking / money transfers ----------------------------------
    if active_attack:
        bank = _task("avoid", "Do not do any banking here. Use your mobile data.")
    elif f["vpn_on"]:
        bank = _task("safe", "Through your VPN, banking is protected even on this "
                             "network.")
    elif f["open_wifi"] or f["transport_unknown"]:
        bank = _task("careful", "For banking, use your mobile data or a VPN rather "
                                "than this network, to be safe.")
    else:
        bank = _task("safe", "No problems found - banking over HTTPS should be "
                             "safe. Always check for the padlock.")

    return [
        {"name": "Browse the web", "icon": "browse", **browse},
        {"name": "Log into accounts", "icon": "login", **login},
        {"name": "Shop / enter card details", "icon": "shop", **shop},
        {"name": "Online banking", "icon": "bank", **bank},
    ]


def _highlights(f: Dict[str, bool]) -> List[Dict[str, str]]:
    h: List[Dict[str, str]] = []
    if f["link_secure"]:
        h.append({"good": True, "text": "The Wi-Fi connection to the router is encrypted."})
    if f["open_wifi"]:
        h.append({"good": False, "text": "This is an open network - people nearby "
                                         "could see unencrypted traffic."})
    if f["evil_twin"]:
        h.append({"good": False, "text": "A possible fake copy of this network was seen."})
    if f["dns_bad"]:
        h.append({"good": False, "text": "You may be redirected to the wrong websites."})
    if f["mitm"]:
        h.append({"good": False, "text": "Signs of someone sitting in the middle of the connection."})
    if f["intercepted"]:
        h.append({"good": False, "text": "Signs that secure (padlock) connections are being read."})
    elif f["transport_ok"]:
        h.append({"good": True, "text": "Your secure (HTTPS) connections tested as private."})
    if f["vpn_on"]:
        h.append({"good": True, "text": "A VPN is active - strong protection on any network."})
    if f["exposed"]:
        h.append({"good": False, "text": "Your own device is exposing services others "
                                         "on this network could reach."})
    if f["hist_changed"]:
        h.append({"good": False, "text": "This network changed since you last used it."})
    return h[:5]


def _stance(result: ScanResult, tasks: List[Dict[str, str]],
            f: Dict[str, bool]) -> Dict[str, str]:
    # The headline is about whether the NETWORK is safe for the things people do
    # (browse, log in, pay). Other risks - like your own device being exposed -
    # are surfaced as warnings in the final action plan instead of overriding it.
    levels = {t["level"] for t in tasks}
    if "avoid" in levels:
        return {"stance": "avoid",
                "headline": "Not safe for passwords, payments, or banking",
                "sub": "Something on this network looks wrong. Keep anything "
                       "sensitive off it - use your mobile data instead."}
    if "careful" in levels:
        return {"stance": "caution",
                "headline": "Okay for browsing - be careful with sensitive things",
                "sub": "General use is fine, but take care before logging in or "
                       "paying. A VPN removes most of the worry."}
    sub = ("No network problems were found. You can browse, log in and pay as "
           "normal - just keep an eye out for the padlock in your browser.")
    if f.get("exposed") or f.get("hist_changed"):
        sub = ("The network is safe for browsing, logging in and payments. See "
               "the action plan below for a couple of things worth tidying up.")
    return {"stance": "safe",
            "headline": "This network looks safe to use", "sub": sub}


def _tips(f: Dict[str, bool]) -> List[str]:
    tips = [
        "Look for the padlock and the correct website address before typing a password.",
        "For banking, prefer the bank's official app over a browser.",
    ]
    if not f["vpn_on"]:
        tips.insert(0, "Turn on a trusted VPN - it protects everything, even on open Wi-Fi.")
    if f["open_wifi"]:
        tips.append("On open Wi-Fi, save anything sensitive for mobile data or a VPN.")
    if f["exposed"]:
        tips.insert(1, "Turn on your firewall and switch off file/printer sharing here.")
    tips.append("Keep your phone and laptop updated so security fixes are in place.")
    return tips[:5]


def _action_plan(f: Dict[str, bool], tasks: List[Dict[str, str]]) -> Dict[str, list]:
    """A final, consolidated report: what you can safely do on this network, and
    what to avoid or tidy up. Combines the per-task verdicts with the secondary
    warnings (device exposure, open network, VPN, history) in one place."""
    CAN = {"browse": "Browse websites and stream video",
           "login":  "Log into your accounts (over HTTPS)",
           "shop":   "Shop and enter card details",
           "bank":   "Do online banking and money transfers"}
    HARD = {"browse": "Avoid this network - even normal browsing isn't trustworthy.",
            "login":  "Do NOT log into any accounts here.",
            "shop":   "Do NOT enter card details here.",
            "bank":   "Do NOT do any banking here."}
    CARE = {"browse": "A fake copy of this network may be nearby - make sure you're on the real one.",
            "login":  "Only log in on sites showing the padlock (HTTPS).",
            "shop":   "Avoid entering card details; prefer mobile data or a VPN.",
            "bank":   "Use mobile data or a VPN for banking, not this network."}

    can, avoid = [], []
    for t in tasks:
        icon, lvl = t.get("icon"), t["level"]
        if lvl == "safe" and icon in CAN:
            can.append(CAN[icon])
        elif lvl == "avoid" and icon in HARD:
            avoid.append(HARD[icon])
        elif lvl == "careful" and icon in CARE:
            avoid.append(CARE[icon])

    # secondary, non-network warnings worth tidying up
    if f.get("exposed"):
        avoid.append("Your device is exposing services others here could reach - "
                     "turn on your firewall and switch off file/printer sharing and "
                     "remote access.")
    if f.get("open_wifi"):
        avoid.append("This is an open network - assume anyone nearby can see "
                     "unencrypted traffic.")
    if f.get("hist_changed"):
        avoid.append("This network changed since last time - confirm it's genuine "
                     "before trusting it.")

    if f.get("vpn_on"):
        can.append("Rely on your VPN - it's encrypting everything you send")
    else:
        can.append("Turn on a VPN for extra protection (recommended on public Wi-Fi)")

    return {"can_do": can, "avoid": avoid}


def summarise(result: ScanResult) -> Dict:
    """Build the plain-language summary block for a finished scan."""
    f = _flags(result)
    tasks = _tasks(f)
    stance = _stance(result, tasks, f)
    return {
        "stance": stance["stance"],
        "headline": stance["headline"],
        "subhead": stance["sub"],
        "tasks": tasks,
        "highlights": _highlights(f),
        "tips": _tips(f),
        "action_plan": _action_plan(f, tasks),
    }


# ========================= demo =========================

from typing import Dict, List


# We disable live online_checks in demo mode and instead inject synthetic
# scanner behaviour by pre-seeding the context. The DNS / portal scanners in
# demo mode read these injected fields (see build()).


SCENARIOS: Dict[str, Dict] = {
    "safe-cafe": {
        "label": "Well-run cafe (WPA2, no anomalies)  -  expected: LOW risk",
        "connected_ssid": "HimalayanBeans_Guest",
        "gateway": "192.168.10.1",
        "dns_servers": ["192.168.10.1", "1.1.1.1"],
        "arp": [("192.168.10.1", "a4:2b:8c:11:22:33"),
                ("192.168.10.20", "de:ad:be:ef:00:01")],
        "aps": [
            ("HimalayanBeans_Guest", "a4:2b:8c:11:22:33", "WPA2-PSK"),
            ("HimalayanBeans_Staff", "a4:2b:8c:11:22:34", "WPA2-PSK"),
        ],
        "dns_hijack": False, "portal_http": False, "tls_bad": False,
    },
    "evil-twin": {
        "label": "Evil twin present (duplicate SSID, mismatched security)  -  expected: HIGH risk",
        "connected_ssid": "College_WiFi",
        "gateway": "10.0.0.1",
        "dns_servers": ["10.0.0.1"],
        "arp": [("10.0.0.1", "00:11:22:33:44:55"),
                ("10.0.0.15", "66:77:88:99:aa:bb")],
        "aps": [
            ("College_WiFi", "00:11:22:33:44:55", "WPA2-PSK"),
            ("College_WiFi", "aa:bb:cc:dd:ee:ff", "Open"),      # the twin
            ("Free WiFi", "12:34:56:78:9a:bc", "Open"),          # bait
        ],
        "dns_hijack": False, "portal_http": True, "tls_bad": False,
    },
    "dns-hijack": {
        "label": "Open network with DNS redirection + ARP MITM  -  expected: DANGEROUS",
        "connected_ssid": "Public_Free_Internet",
        "gateway": "172.16.0.1",
        "dns_servers": ["172.16.0.1"],
        "arp": [("172.16.0.1", "de:ad:be:ef:13:37"),
                ("172.16.0.5", "de:ad:be:ef:13:37"),   # same MAC, 2 IPs = MITM
                ("172.16.0.9", "de:ad:be:ef:13:37")],
        "aps": [
            ("Public_Free_Internet", "de:ad:be:ef:13:37", "Open"),
            ("Public_Free_Internet", "de:ad:be:ef:13:38", "WEP"),
        ],
        "dns_hijack": True, "portal_http": True, "tls_bad": True,
    },
}


def list_scenarios() -> List[str]:
    return list(SCENARIOS.keys())


def build(name: str) -> "DemoContext":
    if name not in SCENARIOS:
        raise KeyError(f"Unknown demo scenario '{name}'. "
                       f"Choose from: {', '.join(SCENARIOS)}")
    s = SCENARIOS[name]
    aps = [AccessPoint(ssid=a[0], bssid=a[1], security=a[2]) for a in s["aps"]]
    return DemoContext(
        connected_ssid=s["connected_ssid"],
        gateway=s["gateway"],
        dns_servers=s["dns_servers"],
        arp_table=s["arp"],
        access_points=aps,
        online_checks=True,
        _dns_hijack=s["dns_hijack"],
        _portal_http=s["portal_http"],
        _tls_bad=s["tls_bad"],
        _label=s["label"],
    )


class DemoContext(ScanContext):
    """
    A ScanContext whose live-network probes (DNS, portal, TLS) are replaced with
    scripted results, so demo runs are deterministic and require no internet.
    The scanners import these flags via monkeypatch-free branches in cli.py.
    """
    def __init__(self, *, _dns_hijack=False, _portal_http=False,
                 _tls_bad=False, _label="", **kwargs):
        super().__init__(**kwargs)
        self.demo = True
        self.dns_hijack = _dns_hijack
        self.portal_http = _portal_http
        self.tls_bad = _tls_bad
        self.label = _label


# ------------------------------------------------------------------ #
#  Self-aliases so the merged engine's P.x()/history.x()/oui.x()      #
#  calls resolve to helpers defined in THIS file.                     #
# ------------------------------------------------------------------ #
P = sys.modules[__name__]
history = sys.modules[__name__]
oui = sys.modules[__name__]



# ------------------------------------------------------------------ #
#  Orchestration + web server (Flask)                                 #
# ------------------------------------------------------------------ #
def build_result(ctx, network_name, mode):
    result = ScanResult(
        network_name=network_name,
        platform=f"{platform.system()} {platform.release()}",
        mode=mode,
        access_points=list(ctx.access_points),
    )
    for scanner in SCANNERS:
        result.dimensions.append(scanner(ctx))
    compute(result)
    return result


def _expected_band(label):
    low = (label or "").lower()
    if "danger" in low: return "expect F"
    if "high" in low:   return "expect D-F"
    if "low" in low:    return "expect A-B"
    return "scenario"


_LAST_RESULT = None


def result_with_advice(result):
    global _LAST_RESULT
    out = result.to_dict()
    out["advice"] = summarise(result)
    _LAST_RESULT = out          # remember it so the assistant can explain it
    return out


# --------------------------------------------------------------------------- #
#  Grounded "explain my result" assistant                                      #
#  Answers from the tool's OWN findings + a small built-in knowledge base.      #
#  It never invents security advice - if it doesn't know, it says so.           #
# --------------------------------------------------------------------------- #
_KB = {
    "evil twin": "An 'evil twin' is a fake Wi-Fi hotspot set up to look exactly "
        "like a real one (same name). If you connect to it, the attacker can watch "
        "or tamper with your traffic. The tool spots it when the same network name "
        "is broadcast with different security settings.",
    "dns": "DNS is the internet's address book - it turns a name like 'yourbank.com' "
        "into the numeric address of the real server. If a network tampers with DNS, "
        "it can send you to a fake copy of a site. The tool checks your answers "
        "against known-good ones to catch this.",
    "vpn": "A VPN encrypts everything you send and routes it through a private "
        "tunnel, so even an unsafe or open network can't read your traffic. It's the "
        "single best thing you can turn on for safety on public Wi-Fi.",
    "https": "HTTPS is the padlock in your browser. It encrypts the connection "
        "between you and a website, so even on an open network your password or card "
        "number can't be read in transit. Always look for the padlock before logging in.",
    "wpa": "WPA2 and WPA3 are the modern Wi-Fi encryption standards. They scramble "
        "the traffic between your device and the router, so people nearby can't read "
        "it. 'Open' (no password) and old 'WEP' networks don't protect you.",
    "open network": "An open network has no password, so the traffic between your "
        "device and the router isn't encrypted - anyone nearby with the right tools "
        "can see unencrypted traffic. HTTPS still protects individual sites, but you "
        "should be careful with anything sensitive.",
    "arp": "ARP spoofing / man-in-the-middle is when someone on the same network "
        "tricks your device into sending traffic through them instead of straight to "
        "the router, so they can watch or alter it. The tool looks for the tell-tale "
        "sign: one device claiming to be several addresses at once.",
    "captive portal": "A captive portal is the sign-in or terms page some networks "
        "show before letting you online. It's risky if it's served over plain HTTP or "
        "uses an invalid certificate, because anything you type could be read.",
    "firewall": "A firewall blocks other devices from connecting to services running "
        "on your computer. With it on, even if your machine is running something like "
        "file sharing, outsiders on the network can't reach it.",
    "device exposure": "This check looks at YOUR OWN device - whether it's running "
        "services (file sharing, remote desktop, databases) that others on the same "
        "Wi-Fi could reach. A firewall normally blocks these; the tool flags them only "
        "when they're actually reachable.",
    "encryption": "Wi-Fi encryption scrambles the traffic between your device and the "
        "router so people nearby can't read it. WPA2/WPA3 = good; Open or WEP = weak.",
    "passive": "PWTDS is a PASSIVE, defensive tool - it never attacks anything. It "
        "reads facts your own computer and connection already expose (Wi-Fi security, "
        "DNS answers, gateway/ARP information, your device's open ports) and makes "
        "ordinary requests. It does NOT scan other people's devices, port-scan peers, "
        "crack passwords, inject packets, or capture credentials, and it can't be "
        "used to harm a network. When something can't be verified, it says \"Can't "
        "tell\" rather than guessing.",
    "privacy": "Nothing you scan is uploaded anywhere. The scan runs on your own "
        "computer and is shown only to you; the only thing kept is a small local "
        "history on your machine that powers the \"changed since last time\" check. "
        "The web helper only listens at 127.0.0.1. In AI mode, your question (and, "
        "when you ask about it, a summary of the scan) is sent to the AI provider "
        "you chose - in offline mode nothing leaves your device at all.",
    "tech": "PWTDS is a small Python (Flask) web app that runs entirely on your own "
        "machine - the pages you see are served locally at 127.0.0.1. The scanners "
        "use your operating system's own network facts (Wi-Fi security details, the "
        "ARP table, DNS servers) plus ordinary DNS and HTTPS probes. The project "
        "also ships a validation harness (validate.py) that proves each detector "
        "fires correctly against controlled test cases.",
    "habits": "The safest habits on public Wi-Fi: (1) treat every public network "
        "as visible - check the padlock (HTTPS) before anything personal, (2) turn "
        "on a VPN so even an open network can't read your traffic, (3) keep file "
        "sharing and remote access off (or use your firewall's Public profile), "
        "(4) think twice before banking or entering passwords on an open network "
        "without a VPN, (5) don't let the browser autofill passwords there, and "
        "(6) run PWTDS first - it tells you exactly what's safe to do here.",
    "dimensions": "PWTDS runs NINE checks on the network you're connected to: "
        "(1) Wi-Fi encryption, (2) evil-twin / fake network detection, "
        "(3) DNS integrity, (4) gateway/ARP man-in-the-middle signs, "
        "(5) HTTPS padlock integrity, (6) captive-portal safety, (7) your own "
        "device's exposure to others on the network, (8) whether the network "
        "changed since your last scan, and (9) whether a VPN is protecting you.",
    "limitation": "Honest limitations of PWTDS: (1) it is a passive, defensive "
        "scanner - it only reads facts from your own connection and can't stop "
        "or attack anything; (2) it sees the network from YOUR device only, not "
        "the whole network; (3) some checks need the internet (a blocked or "
        "offline network means 'Can't tell', not 'safe'); (4) a smart attacker "
        "can hide signs, so a clean report means no red flags were found - not "
        "a 100% guarantee; and (5) it checks the Wi-Fi you're connected to, so "
        "it can't inspect a router's settings or the hotspot provider's "
        "backend.",
}
_TOOL_ANSWERS = {
    "identity": (
        "This is PWTDS - Public Wi-Fi Threat Detection & Risk Assessment System, "
        "and I'm its built-in assistant. It's a small tool that runs entirely on "
        "YOUR computer. Press 'Scan this network' and it checks the Wi-Fi you're "
        "connected to across nine areas: encryption, evil-twin (fake network) "
        "detection, DNS integrity, man-in-the-middle signs, HTTPS padlock "
        "integrity, captive-portal safety, your own device's exposure, whether the "
        "network changed since last time, and VPN protection. You get a plain "
        "verdict - safe / be careful / avoid - for browsing, logging in, shopping "
        "and banking. Everything runs locally and nothing is uploaded."
    ),
    "how": (
        "Nothing to install or configure: join the Wi-Fi as normal, press "
        "'Scan this network', and the scan runs nine checks in about a minute, "
        "then you get a plain-language report - a verdict for browsing, logging "
        "in, shopping and banking, what was checked and found, and a 'your plan "
        "for this network' section. The tool only reads facts your own computer "
        "and connection expose (Wi-Fi security, DNS, gateway, your device's open "
        "ports); it never scans or touches other people's devices."
    ),
}
_TOOL_ID_KW = ["what is this tool", "what's this tool", "what is the tool",
               "what's the tool", "about this tool", "about the tool",
               "tell me about this tool", "tell me about the tool",
               "what is this app", "what's this app", "about this app",
               "what is this program", "what is this software", "tool called",
               "app called", "pwt", "what are you", "who are you", "your name",
               "tell me about yourself"]
_TOOL_HOW_KW = ["how does it work", "how does this work", "how it works",
                "how do i use", "how to use", "how do i scan", "how to scan",
                "what does it check", "what does it do", "what does this do",
                "what does this tool do", "what does the tool do",
                "how does the scan work", "how does the scanning work",
                "how many checks", "nine checks", "what checks"]
_KB_ALIASES = {
    "evil twin": ["evil twin", "fake network", "fake wifi", "clone", "impersonat"],
    "dns": ["dns", "domain name", "web lookup", "website lookup"],
    "vpn": ["vpn"],
    "https": ["https", "padlock", "tls", "ssl", "certificate"],
    "wpa": ["wpa", "wpa2", "wpa3", "wep"],
    "open network": ["open network", "open wifi", "no password", "unencrypted"],
    "arp": ["arp", "man in the middle", "man-in-the-middle", "mitm"],
    "captive portal": ["captive", "portal", "login page", "terms page"],
    "firewall": ["firewall"],
    "device exposure": ["exposed", "exposure", "smb", "file sharing", "port ", "listening"],
    "encryption": ["encryption", "encrypt", "locked"],
    "passive": ["passive", "offensiv", "offensive", "offesive", "hack", "hacking",
            "attack", "crack", "intrusive", "malicious tool", "scan other people",
            "other people's devices", "other devices", "port-scan", "inject",
            "credential"],
    "privacy": ["privacy", "private", "upload", "uploaded", "stored", "store",
                "collect", "track", "tracking", "sent", "cloud", "leave my device"],
    "tech": ["built with", "built in", "how is it made", "how was it made",
             "how is it built", "how does it detect", "written in", "coded in",
             "python", "flask", "framework", "technology", "programmed", "made of"],
    "habits": ["habit", "stay safe on", "safe on public wifi", "safe on public wi-fi",
               "nervous", "protect myself", "tips", "advice for", "what should i do on",
               "how should i", "best practice", "to be safe"],
    "dimensions": ["how many check", "how many dimension", "how many scan",
                   "how many area", "how many thing", "number of check",
                   "dimension"],
    "limitation": ["limitation", "limitations", "limit", "weakness", "drawback",
                   "what can't it do", "what cant it do", "what can't this tool",
                   "what cant this tool", "restriction", "not able to"],
}
_TASK_KEYWORDS = [
    (["bank", "banking", "transfer", "money"], "bank"),
    (["log in", "login", "log into", "sign in", "account", "facebook",
      "instagram", "email", "gmail", "password"], "login"),
    (["shop", "card", "payment", "buy", "checkout", "pay ", "paypal"], "shop"),
    (["browse", "browsing", "surf", "watch", "stream", "youtube", "video"], "browse"),
]
_DIM_KEYWORDS = [
    (["evil twin", "fake network", "real network", "duplicate", "clone", "impersonat"], "ssid_legitimacy"),
    (["dns", "website", "redirect", "lookup", "reaching the real"], "dns_integrity"),
    (["padlock", "https", "tls", "certificate", "secure connection"], "transport_security"),
    (["arp", "man in the middle", "mitm", "middle", "intercept"], "arp_behaviour"),
    (["captive", "portal", "login page", "terms page"], "captive_portal"),
    (["expose", "exposed", "device", "smb", "file sharing", "firewall", "listening", "port"], "device_exposure"),
    (["history", "changed", "last time", "baseline"], "network_history"),
    (["vpn"], "vpn_presence"),
    (["encrypt", "wifi", "wi-fi", "open network", "wpa", "wep", "locked"], "encryption"),
]
_DIM_QUESTION = {
    "encryption": "Is the Wi-Fi itself locked",
    "ssid_legitimacy": "Is this the real network, not a fake",
    "dns_integrity": "Are you reaching the real websites",
    "arp_behaviour": "Is anyone secretly in the middle",
    "transport_security": "Are your padlock (HTTPS) connections private",
    "captive_portal": "Is the login / terms page safe",
    "device_exposure": "Is your own device exposed",
    "network_history": "Has this network changed since last time",
    "vpn_presence": "Are you shielded by a VPN",
}


def _kb_match(q):
    for key, aliases in _KB_ALIASES.items():
        if any(a in q for a in aliases):
            return _KB[key]
    return None


def _r_dim(result, key):
    for d in result.get("dimensions", []):
        if d.get("key") == key:
            return d
    return None


def _worst_finding(d):
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    fs = d.get("findings", [])
    if not fs:
        return None
    return sorted(fs, key=lambda f: order.get(f.get("severity"), 0), reverse=True)[0]


def _task_answer(result, icon):
    for t in result.get("advice", {}).get("tasks", []):
        if t.get("icon") == icon:
            lvl = t["level"]
            lead = {"safe": "Yes, that's fine here.",
                    "careful": "Be careful with that here.",
                    "avoid": "No - I'd avoid that on this network."}[lvl]
            return f"{lead} {t['reason']}"
    return "I couldn't find that activity in the scan."


def _overall_answer(result):
    a = result.get("advice", {})
    tops = []
    for d in result.get("dimensions", []):
        wf = _worst_finding(d)
        if wf and wf.get("severity") not in ("Info", "Low"):
            tops.append(f"- {wf['title']}")
    body = (f"Your network scored {result.get('grade')} "
            f"({result.get('overall_risk')}/100). {a.get('headline','')}. ")
    if tops:
        body += "The main things I found:\n" + "\n".join(tops[:4])
    else:
        body += "No serious problems were found."
    body += "\n\nSee the 'Your plan for this network' section for what you can do and what to avoid."
    return body


def _fix_answer(result):
    recs = []
    for d in result.get("dimensions", []):
        for f in d.get("findings", []):
            if f.get("severity") in ("Critical", "High", "Medium") and f.get("recommendation"):
                recs.append("- " + f["recommendation"])
    recs = list(dict.fromkeys(recs))  # de-dup, keep order
    if not recs:
        avoid = result.get("advice", {}).get("action_plan", {}).get("avoid", [])
        if avoid:
            return "Here's what to watch out for on this network:\n" + \
                   "\n".join("- " + x for x in avoid[:5])
        return "Good news - there's nothing you need to fix on this network right now."
    return "Here's what I'd do:\n" + "\n".join(recs[:5])


def _dim_answer(result, key):
    d = _r_dim(result, key)
    if not d:
        return "That check wasn't part of this scan."
    q = _DIM_QUESTION.get(key, d.get("name", "This check"))
    if not d.get("assessed", True):
        return f"\"{q}?\" - I couldn't check that one on this network (usually " \
               f"because it needs internet and the scan couldn't reach out)."
    wf = _worst_finding(d)
    status = {"Critical": "a problem", "High": "a problem", "Medium": "worth care",
              "Low": "minor", "Info": "fine"}.get(d.get("worst_severity"), "fine")
    out = f"\"{q}?\" - this looks {status}. "
    if wf and wf.get("detail"):
        out += wf["detail"]
    if wf and wf.get("recommendation"):
        out += " " + wf["recommendation"]
    return out


def answer_question(question, result):
    q = (question or "").lower().strip()
    if not q:
        return ("Ask me about your scan - for example: \"is it safe to bank here?\", "
                "\"why is my Wi-Fi flagged?\", or \"what does DNS mean?\"")
    if q in ("hi", "hello", "hey") or (q in ("help", "?")):
        return ("I can explain your scan in plain English. Try: \"is it safe to log "
                "in?\", \"why did it flag my device?\", \"what should I do?\", or ask "
                "what a term means like \"what is an evil twin?\" - or about this "
                "tool itself: \"what is this tool?\"")

    # ---- questions about the tool itself (no scan needed) ----
    if any(a in q for a in _TOOL_HOW_KW):
        return _TOOL_ANSWERS["how"]
    if any(a in q for a in _TOOL_ID_KW):
        return _TOOL_ANSWERS["identity"]

    is_definition = any(p in q for p in ["what is", "what are", "what's", "whats",
                                         "what does", "explain", "meaning", "define"])
    if is_definition:
        kb = _kb_match(q)
        if kb:
            return kb

    if result:
        for kws, icon in _TASK_KEYWORDS:
            if any(k in q for k in kws):
                return _task_answer(result, icon)
        if any(p in q for p in ["grade", "score", "overall", "summary", "how safe",
                                "is it safe", "is this network safe", "why safe",
                                "why unsafe", "unsafe", "dangerous", "why is", "result",
                                "verdict", "what's wrong", "whats wrong"]):
            return _overall_answer(result)
        if any(p in q for p in ["fix", "how do i", "what should i do", "what can i do",
                                "what to do", "avoid", "protect", "make it safe"]):
            return _fix_answer(result)
        for kws, key in _DIM_KEYWORDS:
            if any(k in q for k in kws):
                return _dim_answer(result, key)

    kb = _kb_match(q)
    if kb:
        return kb

    if not result:
        return ("I can't see a scan yet, so I can't comment on YOUR network. But I "
                "can still help: ask me about this tool (\"what is this tool?\"), "
                "how the scan works (\"what does it check?\"), or any security term "
                "(\"what is an evil twin?\", \"what is a VPN?\"). Once you run a "
                "scan, I'll explain your exact result in plain language.")
    return ("I'm not sure about that one. I can explain your result or security "
            "terms - try \"why is my network graded like this?\", \"is it safe to "
            "shop?\", or \"what is an evil twin?\"")


def _load_llm_config():
    """Read AI settings from llm_config.json (or environment). Defaults to Groq,
    so the user only needs to paste their Groq API key. Auto-corrects the most
    common mistakes (Groq key with the wrong URL/model)."""
    cfg = {"api_key": "", "base_url": "https://api.groq.com/openai/v1",
           "model": "llama-3.1-8b-instant"}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llm_config.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for k in cfg:
            if data.get(k):
                cfg[k] = data[k]
    except (OSError, ValueError):
        pass
    cfg["api_key"] = os.environ.get("PWTDS_LLM_API_KEY", cfg["api_key"])
    cfg["base_url"] = os.environ.get("PWTDS_LLM_BASE_URL", cfg["base_url"])
    cfg["model"] = os.environ.get("PWTDS_LLM_MODEL", cfg["model"])

    key = (cfg["api_key"] or "").strip()
    # Treat leftover placeholder text as 'no key'
    if not key or "your" in key.lower() or "paste" in key.lower():
        cfg["api_key"] = ""
        return cfg
    cfg["api_key"] = key

    # Auto-align settings to the key's provider so a small mistake still works.
    if key.startswith("gsk_"):                       # Groq
        if "groq" not in cfg["base_url"]:
            cfg["base_url"] = "https://api.groq.com/openai/v1"
        if (not cfg["model"]) or cfg["model"].lower().startswith("gpt"):
            cfg["model"] = "llama-3.1-8b-instant"
    elif key.startswith("AIza") or key.startswith("AQ."):   # Google Gemini
        cfg["base_url"] = "https://generativelanguage.googleapis.com/v1beta/openai"
        if (not cfg["model"]) or "llama" in cfg["model"].lower() \
                or cfg["model"].lower().startswith("gpt"):
            cfg["model"] = "gemini-flash-latest"
    elif key.startswith("sk-"):                      # OpenAI
        if "groq" in cfg["base_url"] or not cfg["base_url"]:
            cfg["base_url"] = "https://api.openai.com/v1"
        if (not cfg["model"]) or "llama" in cfg["model"].lower():
            cfg["model"] = "gpt-4o-mini"
    return cfg


_ASSISTANT_SYSTEM = (
    "You are the PWTDS Assistant, a friendly guide built into a specific Wi-Fi "
    "security scanner used by non-technical people on public Wi-Fi. Your ONLY "
    "purpose is to explain this tool (PWTDS) and the user's scan results, and to "
    "give plain-language Wi-Fi / online-safety advice.\n\n"
    "MOST IMPORTANT: THE USER IS USING THIS TOOL RIGHT NOW - THIS CHAT IS INSIDE "
    "IT. When the user says 'this tool', 'the tool', 'the app', 'your tool', 'the "
    "scanner', 'the one I'm using', they ALWAYS mean PWTDS - never a third-party "
    "tool or a website. Answer directly about PWTDS; never ask them to describe "
    "what tool they mean.\n\n"
    "WHAT THIS TOOL ACTUALLY IS (never claim it does anything beyond this):\n"
    "PWTDS is a PASSIVE scanner. The user clicks 'Scan this network' and it checks "
    "the Wi-Fi they're connected to across nine areas: (1) Wi-Fi encryption "
    "(Open/WEP/WPA2/WPA3), (2) evil-twin / fake network detection, (3) DNS integrity "
    "(are you reaching real websites), (4) gateway/ARP man-in-the-middle signs, "
    "(5) HTTPS/padlock integrity, (6) captive-portal safety, (7) whether the user's "
    "OWN device is exposing services to the network, (8) whether the network changed "
    "since last time, and (9) whether a VPN is active. It then gives a plain verdict "
    "(safe / be careful / avoid) for browsing, logging in, shopping and banking, plus "
    "a 'Your plan for this network' report. It can also show example threat reports "
    "and a validation harness.\n"
    "The tool does NOT do port scanning of other devices, host discovery, network "
    "reconnaissance, hacking, or anything offensive. It runs entirely on the user's "
    "own machine and uploads nothing.\n\n"
    "RULES:\n"
    "1. When the user asks about THIS network/scan, rely ONLY on the scan summary "
    "provided to you. Do not invent findings or numbers. If no scan has run yet, "
    "say so and suggest pressing 'Scan this network'.\n"
    "2. Never say it's safe to do something the scan flagged as risky.\n"
    "3. If the scan didn't check something ('Can't tell'), say it's unverified, not safe.\n"
    "4. If the question is NOT about PWTDS, the user's scan, or Wi-Fi/online "
    "safety - for example asking how to hack, attack, or exploit a network, or "
    "anything about other software, websites, or general topics - politely stop "
    "and reply with exactly this (keep it brief): 'I'm bound to this tool (PWTDS) "
    "and your scan results only - ask me anything about the tool, your scan, or "
    "staying safe on Wi-Fi.' Do not answer the unrelated question at all.\n"
    "5. Keep answers SHORT: one to three brief paragraphs, never more than about "
    "150 words. ALWAYS finish with a complete final sentence - never trail off "
    "or leave the answer half-written.\n"
    "6. If asked something unrelated to this tool or online safety, gently steer back."
)


def _scan_context_text(result):
    if not result:
        return "No scan has been run yet in this session."
    lines = [f"Scan summary for network '{result.get('network_name','?')}':",
             f"- Overall grade: {result.get('grade')} "
             f"({result.get('overall_risk')}/100)."]
    a = result.get("advice", {})
    if a:
        lines.append(f"- Verdict: {a.get('headline','')}.")
        for t in a.get("tasks", []):
            lines.append(f"- {t.get('name')}: {t.get('level')} - {t.get('reason')}")
        ap = a.get("action_plan", {})
        if ap.get("avoid"):
            lines.append("- Things to avoid: " + "; ".join(ap["avoid"]))
    lines.append("Per-check results:")
    for d in result.get("dimensions", []):
        wf = None
        for f in d.get("findings", []):
            wf = f
            if f.get("severity") not in ("Info",):
                break
        status = d.get("worst_severity") if d.get("assessed", True) else "Can't tell"
        detail = (wf or {}).get("title", "")
        lines.append(f"- {d.get('name')}: {status} ({detail})")
    return "\n".join(lines)


def _llm_chat(messages, cfg, timeout=30):
    """Call the configured LLM provider using only stdlib. Gemini uses its
    native generateContent API (honors system_instruction and has a separate,
    more forgiving free-tier quota pool than the OpenAI-compat proxy); other
    providers use the OpenAI-compatible chat/completions endpoint. Retries
    briefly on rate-limit / transient errors, then fails FAST so the caller
    can fall back to the local answers quickly."""
    if "generativelanguage" in cfg.get("base_url", ""):
        return _gemini_native_chat(messages, cfg, timeout)
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    payload = json.dumps({"model": cfg["model"], "messages": messages,
                          "temperature": 0.3, "max_tokens": 2048}).encode("utf-8")
    for attempt in range(1, 4):
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + cfg["api_key"],
            "User-Agent": "PWTDS/1.0",
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 529):
                raise
            wait = None
            if e.headers:
                wait = e.headers.get("Retry-After")
            try:
                wait = float(wait) if wait else None
            except (TypeError, ValueError):
                wait = None
            if not wait:
                wait = 0.6 * attempt
            time.sleep(min(wait, 3))
    raise RuntimeError("AI provider kept failing after retries")


def _gemini_native_chat(messages, cfg, timeout=30):
    """Call the Gemini native generateContent API. The system prompt goes in
    'system_instruction' (system messages are dropped from the conversation
    history), and chat history uses 'user'/'model' roles."""
    sys_parts, contents = [], []
    for m in messages:
        text = str(m.get("content", ""))
        if m.get("role") == "system":
            sys_parts.append({"text": text})
        elif m.get("role") == "user":
            contents.append({"role": "user", "parts": [{"text": text}]})
        else:
            contents.append({"role": "model", "parts": [{"text": text}]})
    body = {"contents": contents,
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048}}
    if sys_parts:
        body["system_instruction"] = {"parts": sys_parts}
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           + cfg["model"] + ":generateContent?key="
           + urllib.parse.quote(cfg["api_key"]))
    payload = json.dumps(body).encode("utf-8")
    for attempt in range(1, 4):
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "User-Agent": "PWTDS/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 529):
                raise
            wait = None
            if e.headers:
                wait = e.headers.get("Retry-After")
            try:
                wait = float(wait) if wait else None
            except (TypeError, ValueError):
                wait = None
            if not wait:
                wait = 0.6 * attempt
            time.sleep(min(wait, 3))
    raise RuntimeError("AI provider kept failing after retries")


app = Flask(__name__)


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    history = data.get("history") or []
    cfg = _load_llm_config()

    if cfg.get("api_key"):
        try:
            messages = [{"role": "system", "content":
                         _ASSISTANT_SYSTEM + "\n\n" + _scan_context_text(_LAST_RESULT)}]
            for m in history[-8:]:
                role = "assistant" if m.get("role") == "assistant" else "user"
                messages.append({"role": role, "content": str(m.get("content", ""))})
            messages.append({"role": "user", "content": question})
            answer = _llm_chat(messages, cfg)
            return jsonify({"answer": answer, "mode": "ai", "configured": True})
        except Exception as e:
            print(f"[assistant] AI call failed ({type(e).__name__}: {e}) — "
                  f"using offline answers. Check your key/model in llm_config.json.")
            # fall back to offline answers below

    return jsonify({"answer": answer_question(question, _LAST_RESULT),
                    "mode": "offline", "configured": bool(cfg.get("api_key"))})


@app.route("/")
def index():
    return render_template("index.html", page="home")


_LEARN_ICONS = {
    "encryption": '<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
    "evil": '<svg viewBox="0 0 24 24"><rect x="4" y="8" width="11" height="11" rx="2"/><path d="M9 8V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2h-2"/></svg>',
    "dns": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.4 2.5 14.6 0 17M12 3.5c-2.5 2.4-2.5 14.6 0 17"/></svg>',
    "mitm": '<svg viewBox="0 0 24 24"><circle cx="7" cy="9" r="2.4"/><circle cx="17" cy="9" r="2.4"/><path d="M3.5 18.5a3.5 4 0 0 1 7 0M13.5 18.5a3.5 4 0 0 1 7 0"/></svg>',
    "https": '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><circle cx="12" cy="11" r="1.4"/><path d="M12 12.4V15"/></svg>',
    "vpn": '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    "device": '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20M9 16v4M15 16v4"/></svg>',
    "portal": '<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 9.5h18"/></svg>',
}


@app.route("/learn")
def learn():
    topics = [
        {"title": "Wi-Fi encryption", "icon": _LEARN_ICONS["encryption"], "body": _KB["encryption"]},
        {"title": "Evil twin (fake network)", "icon": _LEARN_ICONS["evil"], "body": _KB["evil twin"]},
        {"title": "DNS hijacking", "icon": _LEARN_ICONS["dns"], "body": _KB["dns"]},
        {"title": "Man-in-the-middle", "icon": _LEARN_ICONS["mitm"], "body": _KB["arp"]},
        {"title": "HTTPS / the padlock", "icon": _LEARN_ICONS["https"], "body": _KB["https"]},
        {"title": "Captive portals", "icon": _LEARN_ICONS["portal"], "body": _KB["captive portal"]},
        {"title": "Your device's exposure", "icon": _LEARN_ICONS["device"], "body": _KB["device exposure"]},
        {"title": "VPNs", "icon": _LEARN_ICONS["vpn"], "body": _KB["vpn"]},
    ]
    return render_template("learn.html", page="learn", topics=topics)


@app.route("/history")
def history_page():
    try:
        store = _load()
    except Exception:
        store = {}
    nets = []
    for ssid, fp in (store or {}).items():
        sec = fp.get("security", "")
        nets.append({
            "ssid": ssid,
            "security": sec or "—",
            "open": (not sec) or ("open" in sec.lower()) or ("wep" in sec.lower()),
            "gateway_mac": fp.get("gateway_mac"),
            "dns": ", ".join(fp.get("dns", []) or []),
            "first_seen": (fp.get("first_seen", "") or "").replace("T", " ").replace("+00:00", ""),
            "last_seen": (fp.get("last_seen", "") or "").replace("T", " ").replace("+00:00", ""),
        })
    nets.sort(key=lambda n: n.get("last_seen", ""), reverse=True)
    return render_template("history.html", page="history", networks=nets)


@app.route("/about")
def about():
    return render_template("about.html", page="about")


@app.route("/api/scenarios")
def api_scenarios():
    return jsonify([
        {"name": n, "label": SCENARIOS[n]["label"],
         "expected": _expected_band(SCENARIOS[n]["label"])}
        for n in list_scenarios()
    ])


@app.route("/api/connection")
def api_connection():
    try:
        ssid = get_connected_ssid()
    except Exception:
        ssid = None
    return jsonify({"ssid": ssid})


@app.route("/api/demo")
def api_demo():
    name = request.args.get("scenario", "")
    if not name:
        return jsonify({"error": "missing scenario"}), 400
    try:
        ctx = build(name)
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    result = build_result(ctx, ctx.connected_ssid or name, "demo")
    return jsonify(result_with_advice(result))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    offline = bool(data.get("offline", False))
    ctx = ScanContext.gather(online_checks=not offline)
    network_name = ctx.connected_ssid or ctx.gateway or "current network"
    result = build_result(ctx, network_name, "live")
    return jsonify(result_with_advice(result))


if __name__ == "__main__":
    import webbrowser, threading
    PORT = int(os.environ.get("PORT", "8765"))
    url = f"http://127.0.0.1:{PORT}/"
    print("PWTDS v1.1 - Wi-Fi Security Scanner  (pages: Scan, Learn, History, About)")
    print("-" * 52)
    print(f"  Open: {url}")
    print("  (your browser should open automatically)")
    print("  Press Ctrl+C here to stop.")
    _cfg = _load_llm_config()
    if _cfg.get("api_key"):
        print(f"  AI assistant: ON  (model: {_cfg['model']})")
    else:
        print("  AI assistant: offline mode — paste a free Groq key in "
              "llm_config.json to enable full chat.")
    print("-" * 52)
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=PORT, debug=False)

