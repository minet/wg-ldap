from __future__ import annotations

import json
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Dict, Generator, Iterable, List
import logging
import urllib.request
import urllib.error

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LDAPUser:
    uid: str
    public_key: str
    groups: List[str]


@dataclass
class Peer:
    uid: str
    public_key: str
    address: IPv4Address
    groups: List[str]


class IPAM:
    def __init__(self, state_file: str, vpn_address: str) -> None:
        self.path = Path(state_file)
        self.network: IPv4Network = IPv4Network(vpn_address, strict=False)
        self.state: Dict[str, str] = {}
        self._load()
        log.debug(
            "IPAM initialized: network=%s state_entries=%d", self.network, len(self.state)
        )

    def _load(self) -> None:
        try:
            if self.path.exists():
                self.state = json.loads(self.path.read_text(encoding="utf-8"))
            else:
                self.state = {}
        except Exception:
            self.state = {}

    def save(self) -> None:
        log = logging.getLogger(__name__)
        log.debug("Saving IPAM state to %s (entries=%d)", self.path, len(self.state))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def _addresses(self) -> Iterable[IPv4Address]:
        # Reserve the first address for the server
        for ip in self.network.hosts():
            if ip == list(self.network.hosts())[0]:
                # skip first host (likely used by server config)
                continue
            yield ip

    def load_state_from_master(self, master_address: str, master_port: int, preshared_key: str) -> None:
        url = f"http://{master_address}:{master_port}/iplist/{preshared_key}"
        log.debug("Loading IPAM state from master: %s", url)

        try:
            with urllib.request.urlopen(url) as response:
                if response.status == 200:
                    data = response.read().decode('utf-8')
                    self.state = json.loads(data)
                    log.info("Successfully loaded IPAM state from master (entries=%d)", len(self.state))
                else:
                    log.warning("Failed to load state from master: HTTP %d", response.status)
        except urllib.error.URLError as e:
            log.error("Failed to connect to master: %s", e)
        except json.JSONDecodeError as e:
            log.error("Invalid JSON response from master: %s", e)
        except Exception as e:
            log.error("Unexpected error loading state from master: %s", e)
        

    def assign_peers(self, users: Iterable[LDAPUser], persist: bool = True, assign_ips: bool = True) -> List[Peer]:
        # Keep existing allocations
        allocated: Dict[str, IPv4Address] = {
            uid: IPv4Address(addr) for uid, addr in self.state.items()
        }

        # Build reverse map of used addresses
        used = set(allocated.values())

        def next_free() -> Generator[IPv4Address]:
            for ip in self._addresses():
                if ip not in used:
                    used.add(ip)
                    yield ip
            raise RuntimeError("No free IP addresses available in VPN network")

        peers: List[Peer] = []
        addresses = next_free()
        for u in users:
            addr = allocated.get(u.uid)
            if addr is None and assign_ips:
                addr = next(addresses)
                allocated[u.uid] = addr
                log.debug("Allocated %s -> %s", u.uid, addr)
            elif addr is None and not assign_ips:
                log.warning("No IP was assigned to %s, this node is not configured to give out IP addresses.", u.uid)
                continue
            else:
                assert addr is not None, "liteapp is dumb" # To make the type checker happy ig
            peers.append(Peer(uid=u.uid, public_key=u.public_key, address=addr, groups=u.groups))

        if persist:
            self.state = {uid: str(ip) for uid, ip in allocated.items()}
        return peers
