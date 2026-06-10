"""
Unified firewall provider abstraction for local OS and external WAF integrations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

from security.firewall import apply_firewall_block, remove_firewall_block, validate_ip


class FirewallProvider(ABC):
    provider_id: str
    display_name: str

    @abstractmethod
    def block_ip(self, ip_address: str, reason: str = "") -> Tuple[bool, str]:
        ...

    @abstractmethod
    def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        ...

    def is_available(self) -> bool:
        return True


class LocalOSProvider(FirewallProvider):
    provider_id = "local_os"
    display_name = "Local OS Firewall (netsh/iptables)"

    def block_ip(self, ip_address: str, reason: str = "") -> Tuple[bool, str]:
        return apply_firewall_block(ip_address)

    def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        return remove_firewall_block(ip_address)


class CloudflareWAFProvider(FirewallProvider):
    provider_id = "cloudflare_waf"
    display_name = "Cloudflare WAF"

    def is_available(self) -> bool:
        import os

        return bool(os.environ.get("CLOUDFLARE_API_TOKEN") and os.environ.get("CLOUDFLARE_ZONE_ID"))

    def block_ip(self, ip_address: str, reason: str = "") -> Tuple[bool, str]:
        if not validate_ip(ip_address):
            return False, "Invalid IP address"
        if not self.is_available():
            return (
                False,
                "Cloudflare credentials not configured (CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)",
            )
        try:
            import os
            import urllib.error
            import urllib.request

            token = os.environ["CLOUDFLARE_API_TOKEN"]
            zone_id = os.environ["CLOUDFLARE_ZONE_ID"]
            payload = (
                '{"mode":"block","configuration":{"target":"ip","value":"'
                + ip_address
                + '"},"notes":"CDS block: '
                + (reason or "manual")
                + '"}'
            )
            req = urllib.request.Request(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules",
                data=payload.encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status in (200, 201):
                    return True, f"Cloudflare WAF block applied for {ip_address}"
                return False, f"Cloudflare API returned status {resp.status}"
        except Exception as exc:
            return False, f"Cloudflare block failed: {exc}"

    def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        if not self.is_available():
            return False, "Cloudflare credentials not configured"
        return False, "Cloudflare unblock requires rule ID lookup (not implemented without live API)"


class EnterpriseAPIProvider(FirewallProvider):
    provider_id = "enterprise_api"
    display_name = "Enterprise Network Firewall API"

    def is_available(self) -> bool:
        import os

        return bool(os.environ.get("ENTERPRISE_FW_API_URL") and os.environ.get("ENTERPRISE_FW_API_KEY"))

    def block_ip(self, ip_address: str, reason: str = "") -> Tuple[bool, str]:
        if not self.is_available():
            return False, "Enterprise firewall API not configured (ENTERPRISE_FW_API_URL, ENTERPRISE_FW_API_KEY)"
        return False, "Enterprise API integration requires live appliance endpoint"

    def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        return False, "Enterprise API integration requires live appliance endpoint"


PROVIDERS: Dict[str, FirewallProvider] = {
    "local_os": LocalOSProvider(),
    "cloudflare_waf": CloudflareWAFProvider(),
    "enterprise_api": EnterpriseAPIProvider(),
}


def get_provider(provider_id: str) -> Optional[FirewallProvider]:
    return PROVIDERS.get(provider_id)


def list_providers() -> List[Dict[str, object]]:
    return [
        {
            "provider_id": p.provider_id,
            "display_name": p.display_name,
            "available": p.is_available(),
        }
        for p in PROVIDERS.values()
    ]


def orchestrate_block(
    ip_address: str,
    reason: str,
    provider_id: str = "local_os",
    ttl_seconds: int = 3600,
) -> Dict[str, object]:
    """Block IP via selected provider and record with TTL."""
    import time

    from storage.persistence import get_store

    if not validate_ip(ip_address):
        return {"success": False, "message": "Invalid IP address"}

    provider = get_provider(provider_id) or PROVIDERS["local_os"]
    applied, message = provider.block_ip(ip_address, reason)
    expires_at = time.time() + max(60, ttl_seconds)
    get_store().save_blocked_ip(
        ip_address,
        reason,
        applied,
        provider=provider_id,
        ttl_seconds=ttl_seconds,
        expires_at=expires_at,
    )
    return {
        "success": True,
        "firewall_applied": applied,
        "message": message,
        "provider": provider_id,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
    }


def expire_stale_blocks() -> int:
    """Remove expired IP blocks. Returns count of expired entries."""
    import time

    from storage.persistence import get_store

    store = get_store()
    expired = store.list_expired_blocked_ips(time.time())
    count = 0
    for row in expired:
        provider = get_provider(row.get("provider", "local_os")) or PROVIDERS["local_os"]
        provider.unblock_ip(row["ip_address"])
        store.unblock_ip(row["ip_address"])
        count += 1
    return count


__all__ = [
    "FirewallProvider",
    "LocalOSProvider",
    "CloudflareWAFProvider",
    "EnterpriseAPIProvider",
    "get_provider",
    "list_providers",
    "orchestrate_block",
    "expire_stale_blocks",
]
