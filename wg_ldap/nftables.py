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
        lines.append("table inet filter {")
        lines.append("\tchain input {")
        lines.append("\t\ttype filter hook input priority 0;")
        lines.append("\t\tpolicy drop;")
        lines.append("\t\tiif lo accept")
        lines.append("\t\tct state established,related accept")
        for port in cfg.nftables.input_allow_tcp:
            lines.append(f"\t\ttcp dport {port} accept")
        for port in cfg.nftables.input_allow_udp:
            lines.append(f"\t\tudp dport {port} accept")
        lines.append("\t}")

        lines.append("\tchain forward {")
        lines.append("\t\ttype filter hook forward priority 0;")
        lines.append("\t\tpolicy drop;")
        # Only allow return traffic from interfaces to VPN
        for rule in cfg.nftables.forward_policies:
            iif = rule.get("iif")
            oif = rule.get("oif")
            lines.append(
                f"\t\tiifname \"{oif}\" oifname \"{iif}\" ct state established,related accept"
            )
        # VPN to interfaces rules will be added by per-client ACLs only
        lines.append("\t}")
        lines.append("}")

        lines.append("")
        lines.append("table ip nat {")
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
    for peer in peers:
        routes = []
        # Add group routes
        for g in peer.groups:
            routes.extend(cfg.per_group_routes.get(g, []))
        routes = _unique(routes)
        for route in routes:
            per_client_lines.append(
                f"add rule inet filter forward ip saddr {peer.address} ip daddr {route} accept"
            )

    if per_client_lines:
        lines.append("")
        lines.append("# Per-client ACLs")
        lines.extend(per_client_lines)

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
