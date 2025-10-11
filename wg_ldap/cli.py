from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Tuple

import subprocess

from .config import AppConfig, load_config, write_example_config
from .ipam import IPAM
from .ldap_sync import LDAPClient
from .nftables import render_nftables
from .utils import atomic_write, run_cmd
from .wireguard import render_wireguard


def gen_nft_base(args: argparse.Namespace) -> int:
    """Génère un nftables.base.conf pour les interfaces données, écrit dans base_path de la config."""
    if not args.config:
        print("--config est requis pour gen-nft-base", file=sys.stderr)
        return 1
    cfg = load_config(Path(args.config).expanduser())
    nics = args.interfaces
    if not cfg.nftables.base_path:
        print("nftables.base_path doit être défini dans la config TOML", file=sys.stderr)
        return 1
    # Build forward policies and nat rules for each interface
    forward_policies = [{"iif": "wg0", "oif": nic} for nic in nics]
    nat_postrouting = [{"oif": nic, "saddr": cfg.vpn_network().network_address, "action": "masquerade"} for nic in nics]
    # Compose a dummy NFTablesConfig for base rendering
    nft_cfg = cfg.nftables.model_copy(update={
        "forward_policies": forward_policies,
        "nat_postrouting": nat_postrouting,
        "base_path": None,
        "base_content": None,
    })
    dummy_cfg = cfg.model_copy(update={"nftables": nft_cfg})
    base = render_nftables(dummy_cfg, [])
    Path(cfg.nftables.base_path).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg.nftables.base_path).write_text(base, encoding="utf-8")
    print(f"Base nftables config écrite dans {cfg.nftables.base_path}")
    return 0


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def cmd_init(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    if config_path.exists() and not args.force:
        print(f"Refusing to overwrite existing file: {config_path}", file=sys.stderr)
        return 1
    write_example_config(config_path)
    print(f"Wrote example config to {config_path}")
    return 0


def _load_all(config_path: Path) -> Tuple[AppConfig, LDAPClient, IPAM]:
    cfg = load_config(config_path)
    ldap_client = LDAPClient(cfg.ldap)
    ipam = IPAM(cfg.web.state_file, cfg.wireguard.address)
    return cfg, ldap_client, ipam


def _write_if_changed(path: str, content: str) -> bool:
    """Write content to path if changed. Returns True if file was changed."""
    p = Path(path)
    if p.exists() and p.read_text(encoding="utf-8") == content:
        return False
    atomic_write(path, content)
    return True

def cmd_sync(args: argparse.Namespace) -> int:
    logging.debug("Starting sync with config: %s", args.config)
    cfg, ldap_client, ipam = _load_all(Path(args.config).expanduser())
    logging.debug(
        "Effective paths: wireguard.config_output_path=%s web.state_file=%s nftables.output_path=%s",
        cfg.wireguard.config_output_path,
        cfg.web.state_file,
        cfg.nftables.output_path,
    )

    logging.debug("Querying LDAP users…")
    users = ldap_client.get_users()
    logging.info("Fetched %d LDAP users", len(users))

    # Assign and persist IP addresses
    logging.debug("Assigning IPs to %d users", len(users))
    peers = ipam.assign_peers(users)
    logging.debug("Assigned %d peers; persisting state", len(peers))
    ipam.save()

    # Render configs
    logging.debug("Rendering WireGuard config…")
    wg_conf = render_wireguard(cfg, peers)
    logging.debug("Rendering nftables config…")
    nft_conf = render_nftables(cfg, peers)

    # Write files only if changed
    logging.debug("Writing WireGuard config to %s", cfg.wireguard.config_output_path)
    wg_changed = _write_if_changed(cfg.wireguard.config_output_path, wg_conf)
    if wg_changed:
        logging.info("Wrote WireGuard config to %s (changed)", cfg.wireguard.config_output_path)
    else:
        logging.info("WireGuard config unchanged at %s", cfg.wireguard.config_output_path)

    nft_changed = False
    logging.debug("Writing nftables config to %s", cfg.nftables.output_path)
    nft_changed = _write_if_changed(cfg.nftables.output_path, nft_conf)
    if nft_changed:
        logging.info("Wrote nftables config to %s (changed)", cfg.nftables.output_path)
    else:
        logging.info("nftables config unchanged at %s", cfg.nftables.output_path)

    if args.apply:
        # Apply WireGuard config
        logging.debug("Applying WireGuard config via wg syncconf")
        # Use syncconf with wg-quick strip for safer config updates
        strip_result = run_cmd(["wg-quick", "strip", cfg.wireguard.config_output_path], capture_output=True)
        
        # Write stripped config to temporary file and use it with syncconf
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as tmp_file:
            tmp_file.write(strip_result.stdout)
            tmp_file_path = tmp_file.name
        
        try:
            run_cmd(["wg", "syncconf", cfg.wireguard.interface, tmp_file_path])
            logging.info("Applied WireGuard configuration to %s", cfg.wireguard.interface)
        finally:
            os.unlink(tmp_file_path)

        # Apply nftables config
        logging.debug("Applying nftables config via nft -f")
        run_cmd(["/usr/sbin/nft", "-f", cfg.nftables.output_path])
        logging.info("Applied nftables configuration")

    if args.print:
        print("# --- WireGuard config ---")
        print(wg_conf)
        print("\n# --- nftables config ---")
        print(nft_conf)

    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    logging.debug("Generating configs with config: %s", args.config)
    cfg, ldap_client, ipam = _load_all(Path(args.config).expanduser())
    logging.debug("Querying LDAP users…")
    users = ldap_client.get_users()
    logging.debug("Assigning IPs (no persist)")
    peers = ipam.assign_peers(users, persist=False)
    logging.debug("Rendering WireGuard and nftables configs…")
    wg_conf = render_wireguard(cfg, peers)
    nft_conf = render_nftables(cfg, peers)
    if args.output:
        logging.debug("Writing outputs to configured paths")
        atomic_write(cfg.wireguard.config_output_path, wg_conf)
        atomic_write(cfg.nftables.output_path, nft_conf)
    print(wg_conf)
    print("\n# --- nftables ---\n")
    print(nft_conf)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config).expanduser())
    # Shallow validation via model
    print("Config OK:\n" + json.dumps(cfg.model_dump(), indent=2, default=str))
    # Connectivity check
    ldap_client = LDAPClient(cfg.ldap)
    users = ldap_client.get_users(limit=1)
    print(f"LDAP connectivity OK, sample users fetched: {len(users)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wg-ldap", description="Sync WireGuard peers from LDAP and generate firewall rules.")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    sp = p.add_subparsers(dest="command", required=True)

    p_init = sp.add_parser("init-config", help="Write an example config file")
    p_init.add_argument("--config", default="/etc/wg-ldap/config.toml", help="Path to write the example config")
    p_init.add_argument("--force", action="store_true", help="Overwrite if exists")
    p_init.set_defaults(func=cmd_init)

    p_sync = sp.add_parser("sync", help="Fetch from LDAP, update config files, and optionally apply")
    p_sync.add_argument("--config", default="/etc/wg-ldap/config.toml", help="Path to config file")
    p_sync.add_argument("--apply", action="store_true", help="Apply the generated configs (wg setconf, nft -f)")
    p_sync.add_argument("--print", action="store_true", help="Print generated configs to stdout as well")
    p_sync.set_defaults(func=cmd_sync)

    p_gen = sp.add_parser("generate", help="Only generate configs, do not apply")
    p_gen.add_argument("--config", default="/etc/wg-ldap/config.toml", help="Path to config file")
    p_gen.add_argument("--output", action="store_true", help="Write outputs to configured paths as files")
    p_gen.set_defaults(func=cmd_generate)

    p_val = sp.add_parser("validate", help="Validate config and LDAP connectivity")
    p_val.add_argument("--config", default="/etc/wg-ldap/config.toml", help="Path to config file")
    p_val.set_defaults(func=cmd_validate)

    p_gen_nft = sp.add_parser("gen-nft-base", help="Génère un nftables.base.conf pour une liste d'interfaces")
    p_gen_nft.add_argument("interfaces", nargs="+", help="Liste des interfaces internes (ex: eth0 eth1 eth2)")
    p_gen_nft.add_argument("--config", default="/etc/wg-ldap/config.toml", help="Fichier de config TOML à utiliser pour les ports/policies")
    p_gen_nft.set_defaults(func=gen_nft_base)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001
        logging.exception("Unhandled error: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
