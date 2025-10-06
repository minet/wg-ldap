from __future__ import annotations

from typing import Iterable, List
import logging

from .config import AppConfig
from .ipam import Peer


def render_wireguard(cfg: AppConfig, peers: Iterable[Peer]) -> str:
    log = logging.getLogger(__name__)
    lines: List[str] = []
    wg = cfg.wireguard
    lines.append("[Interface]")
    with open(wg.private_key_path, 'r') as f:
        private_key = f.read().strip()
    lines.append(f"PrivateKey = {private_key}")
    lines.append(f"Address = {wg.address}")
    lines.append(f"ListenPort = {wg.port}")
    if wg.mtu:
        lines.append(f"MTU = {wg.mtu}")
    if wg.table is not None:
        lines.append(f"Table = {wg.table}")
    lines.append("")

    base_allowed = list(wg.peers_base_allowed_ips)

    count = 0
    for peer in peers:
        lines.append("[Peer]")
        lines.append(f"# uid={peer.uid}")
        lines.append(f"PublicKey = {peer.public_key}")
        allowed_ips = base_allowed + [f"{peer.address}/32"]
        lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
        lines.append("")
        count += 1

    log.debug("Rendered WireGuard config with %d peers", count)
    return "\n".join(lines).strip() + "\n"
