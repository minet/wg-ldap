from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Set
import logging

from pathlib import Path

from .config import AppConfig
from .ipam import Peer


def _unique(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    res: List[str] = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            res.append(s)
    return res


def render_nftables(cfg: AppConfig, peers: Iterable[Peer]) -> str:
    log = logging.getLogger(__name__)
    base_content: str | None = cfg.nftables.base_content

    lines: List[str] = []
    if base_content is None:
        # Fallback: generate a base ruleset
        lines.append("flush ruleset")
        lines.append("")
        lines.append("table inet filter {")
        lines.append("\tchain input {")
        lines.append("\t\ttype filter hook input priority 0;")
        lines.append("\t\tpolicy drop;")
        lines.append("\t\tiif lo accept")
        lines.append("\t\tct state established,related accept")
        for port in cfg.nftables.input_allow_tcp:
            lines.append(f"\t\ttcp dport {port} accept")
        lines.append(f"\t\ttcp dport {cfg.web.port} accept")
        for port in cfg.nftables.input_allow_udp:
            lines.append(f"\t\tudp dport {port} accept")
        lines.append("\t\ticmp type echo-request accept")
        lines.append("\t\ticmpv6 type echo-request accept")
        lines.append("\t}")

        lines.append("\tchain forward {")
        lines.append("\t\ttype filter hook forward priority 0;")
        lines.append("\t\tpolicy drop;")
        lines.append("\t\tct state established,related accept")
        lines.append(f"\t\tip saddr {cfg.wireguard.address} ip daddr {cfg.wireguard.address} accept")
        # Only allow return traffic from interfaces to VPN
        for rule in cfg.nftables.forward_policies:
            iif = rule.get("iif")
            oif = rule.get("oif")
            lines.append(
                f"\t\tiifname \"{oif}\" oifname \"{iif}\" ct state established,related accept"
            )
        # Allow everything public
        lines.append("\t\tip saddr 10.8.0.0/16 ip daddr != 10.0.0.0/8 ip daddr != 172.16.0.0/12 ip daddr != 192.168.0.0/16 accept")
        # VPN to interfaces rules will be added by per-client ACLs only
        lines.append("\t}")
        lines.append("}")

        lines.append("")
        lines.append("table ip nat {")
        lines.append("\tchain prerouting {")
        lines.append("\t\ttype nat hook prerouting priority -100;")
        lines.append("\t}")
        lines.append("\tchain postrouting {")
        lines.append("\t\ttype nat hook postrouting priority 100;")
        for nat in cfg.nftables.nat_postrouting:
            oif = nat.get("oif")
            saddr = nat.get("saddr")
            action = nat.get("action", "masquerade")
            lines.append(f"\t\toifname \"{oif}\" ip saddr {saddr} {action}")
        lines.append("\t}")
        lines.append("}")
    else:
        # Use provided base content as-is
        lines.append(base_content.rstrip("\n"))

    # Per-client ACLs by source address and target routes
    per_client_lines: List[str] = []
    per_client_dns_lines: List[str] = []
    
    # Extract WireGuard server address (without CIDR)
    wg_address = cfg.wireguard.address.split('/')[0]
    
    for peer in peers:
        routes = []
        target_dns_list = cfg.per_group_dns.get("*", None)  # Default DNS if any
        target_dns_index = -1
        
        # Add group routes and find DNS server
        for g in peer.groups:
            routes.extend(cfg.per_group_routes.get(g, []))
            # Get DNS server for this group (last matching wins)
            if g in cfg.per_group_dns and (index := list(cfg.per_group_dns).index(g)) >= target_dns_index:
                target_dns_list = cfg.per_group_dns[g]
                target_dns_index = index

        routes = _unique(routes)
        for route in routes:
            per_client_lines.append(
                f"add rule inet filter forward ip saddr {peer.address} ip daddr {route} accept"
            )
        
        # DNS redirection: use the last matching DNS server
        # If multiple DNS servers are available for the group used, use group[ip % len] to distribute
        if target_dns_list:
            target_dns = target_dns_list[ int(peer.address) % len(target_dns_list)]
            # DNAT for UDP DNS queries
            per_client_dns_lines.append(
                f"add rule ip nat prerouting ip saddr {peer.address} ip daddr {wg_address} udp dport 53 dnat to {target_dns}"
            )
            # DNAT for TCP DNS queries
            per_client_dns_lines.append(
                f"add rule ip nat prerouting ip saddr {peer.address} ip daddr {wg_address} tcp dport 53 dnat to {target_dns}"
            )

    if per_client_lines:
        lines.append("")
        lines.append("# Per-client ACLs")
        lines.extend(per_client_lines)
    
    if per_client_dns_lines:
        lines.append("")
        lines.append("# Per-client DNS redirections")
        lines.extend(per_client_dns_lines)

    if base_content is None:
        log.debug(
            "Rendered nftables (generated base): input_tcp=%d input_udp=%d forward_policies=%d nat_rules=%d per_client_rules=%d",
            len(cfg.nftables.input_allow_tcp),
            len(cfg.nftables.input_allow_udp),
            len(cfg.nftables.forward_policies),
            len(cfg.nftables.nat_postrouting),
            len(per_client_lines),
        )
    else:
        log.debug(
            "Rendered nftables (imported base): per_client_rules=%d",
            len(per_client_lines),
        )
    return "\n".join(lines).strip() + "\n"
