"""
IP blocking with OS firewall integration and persistent fallback.
"""

import platform
import re
import subprocess
import threading
from typing import Dict, Tuple

from security.config import firewall_enabled

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

_lock = threading.Lock()
_applied_rules: Dict[str, str] = {}


def validate_ip(ip_address: str) -> bool:
    return bool(_IP_RE.match(ip_address))


def _rule_name(ip_address: str) -> str:
    return f"CDS_Block_{ip_address.replace('.', '_')}"


def apply_firewall_block(ip_address: str) -> Tuple[bool, str]:
    """
    Apply inbound block rule. Returns (applied, message).
    """
    if not validate_ip(ip_address):
        return False, "Invalid IP address format"

    if not firewall_enabled():
        return False, "Firewall integration disabled (recorded in policy store only)"

    system = platform.system().lower()
    rule_name = _rule_name(ip_address)

    with _lock:
        if ip_address in _applied_rules:
            return True, f"Rule already active for {ip_address}"

        try:
            if system == "windows":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip_address}",
                    "enable=yes",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15, check=False
                )
                if result.returncode != 0:
                    return False, (result.stderr or result.stdout or "netsh failed").strip()
                _applied_rules[ip_address] = rule_name
                return True, f"Windows firewall rule '{rule_name}' applied"

            if system == "linux":
                cmd = [
                    "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15, check=False
                )
                if result.returncode != 0:
                    return False, (result.stderr or result.stdout or "iptables failed").strip()
                _applied_rules[ip_address] = "iptables"
                return True, f"iptables DROP rule applied for {ip_address}"

            return False, f"No firewall adapter for platform '{system}' (policy recorded only)"

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
            return False, f"Firewall operation failed: {exc}"


def remove_firewall_block(ip_address: str) -> Tuple[bool, str]:
    if not validate_ip(ip_address):
        return False, "Invalid IP address format"

    system = platform.system().lower()
    rule_name = _rule_name(ip_address)

    with _lock:
        if ip_address not in _applied_rules and system != "windows":
            return True, "No active firewall rule tracked for this IP"

        try:
            if system == "windows":
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
            elif system == "linux":
                cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)

            _applied_rules.pop(ip_address, None)
            return True, f"Firewall rule removed for {ip_address}"
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
            return False, f"Firewall removal failed: {exc}"
