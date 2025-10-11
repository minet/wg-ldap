from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network
from pathlib import Path
import logging
log = logging.getLogger(__name__)
from typing import Iterable, Mapping

try:  # Python 3.11+
    import tomllib  # type: ignore[no-redef]
except Exception:  # Python 3.10 fallback
    import tomli as tomllib  # type: ignore[assignment]
from pydantic import BaseModel, Field, HttpUrl, ValidationError


class LDAPConfig(BaseModel):
    url: HttpUrl | str
    bind_dn: str
    password: str
    base_dn: str
    user_filter: str = "(objectClass=person)"
    attributes: list[str] = Field(default_factory=lambda: ["uid", "sshPublicKey", "memberOf"]) 


class WireGuardConfig(BaseModel):
    interface: str = "wg0"
    private_key_path: str = "/etc/wireguard/server_private.key"
    address: str = "10.8.0.1/16"
    port: int = 51820
    mtu: int | None = None
    table: str | int | None = None
    peers_base_allowed_ips: list[str] = Field(default_factory=list)


class NFTablesConfig(BaseModel):
    output_path: str = "/etc/nftables.conf"
    base_path: str | None = None
    base_content: str | None = None
    input_allow_tcp: list[int] = Field(default_factory=lambda: [22])
    input_allow_udp: list[int] = Field(default_factory=lambda: [51825])
    forward_policies: list[dict] = Field(
        default_factory=lambda: [
            {"iif": "wg0", "oif": "eth0", "action": "accept"},
            {"iif": "wg0", "oif": "eth1", "action": "accept"},
            {"iif": "wg0", "oif": "eth2", "action": "accept"},
        ]
    )
    nat_postrouting: list[dict] = Field(
        default_factory=lambda: [
            {"oif": "eth0", "saddr": "10.8.0.0/16", "action": "masquerade"},
            {"oif": "eth1", "saddr": "10.8.0.0/16", "action": "masquerade"},
            {"oif": "eth2", "saddr": "10.8.0.0/16", "action": "masquerade"},
        ]
    )


class WebConfig(BaseModel):
    host: str = "127.0.0.1"
    external_vpn_ip: str = "1.1.1.1"
    port: int = 8080


class AppConfig(BaseModel):
    ldap: LDAPConfig
    wireguard: WireGuardConfig = Field(default_factory=WireGuardConfig)
    nftables: NFTablesConfig = Field(default_factory=NFTablesConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    wg_conf_output: str = "/etc/wireguard/wg0.conf"
    vpn_cidr: str = "10.8.0.0/16"
    state_file: str = "/var/lib/wg-ldap/state.json"
    per_group_routes: dict[str, list[str]] = Field(default_factory=dict)
    per_group_dns: dict[str, str] = Field(default_factory=dict)

    def vpn_network(self) -> IPv4Network:
        return IPv4Network(self.vpn_cidr)


def _read_toml(path: Path) -> Mapping:
    log.debug("Reading TOML config from %s", path)
    with Path(path).open("rb") as f:
        data = tomllib.load(f)
    log.debug("Loaded config keys: %s", list(data.keys()))
    return data


def load_config(path: Path) -> AppConfig:
    try:
        data = _read_toml(path)
        cfg = AppConfig.model_validate(data)
        # Load nftables base content if specified
        if cfg.nftables.base_path:
            try:
                p = Path(cfg.nftables.base_path)
                cfg.nftables.base_content = p.read_text(encoding="utf-8")
                log.debug(
                    "Loaded nftables base content from %s (%d bytes)",
                    p,
                    len(cfg.nftables.base_content or ""),
                )
            except FileNotFoundError:
                log.warning(
                    "nftables.base_path points to missing file: %s; will fall back to generated base",
                    cfg.nftables.base_path,
                )
        # Fallback: some users may place top-level keys under [nftables] inadvertently.
        nft_raw = data.get("nftables", {}) if isinstance(data, dict) else {}
        def _maybe_override(field: str) -> None:
            if field not in data and field in nft_raw:
                old = getattr(cfg, field)
                new = nft_raw[field]
                setattr(cfg, field, new)
                log.warning(
                    "Config key '%s' found under [nftables]; overriding default (%s) with %s. "
                    "Move '%s' to top-level to avoid this warning.",
                    field,
                    old,
                    new,
                    field,
                )
        for key in ("wg_conf_output", "vpn_cidr", "state_file"):
            _maybe_override(key)
        log.debug(
            "Validated config: interface=%s wg_conf_output=%s vpn_cidr=%s",
            cfg.wireguard.interface,
            cfg.wg_conf_output,
            cfg.vpn_cidr,
        )
        return cfg
    except FileNotFoundError as e:
        raise SystemExit(f"Config file not found: {path}") from e
    except ValidationError as e:  # noqa: TRY003
        raise SystemExit(f"Invalid configuration: {e}") from e


EXAMPLE_CONFIG = """
# wg-ldap configuration

# Fichier de sortie de la configuration WireGuard
wg_conf_output = "/etc/wireguard/wg0.conf"
# CIDR du VPN WireGuard
vpn_cidr = "10.8.0.0/16"
# Fichier d'état pour savoir quelles IP ont été attribuées
state_file = "/var/lib/wg-ldap/ips.json"


[ldap]
url = "ldap://ldap.example.com"
# Utilisateur avec droits de lecture sur les entrées utilisateurs
bind_dn = "cn=inspector,dc=minet,dc=net"
# Mot de passe de l'utilisateur 
password = "DEMANDERLEMOTDEPASSEAQUELQUUN"
# Base DN pour la recherche des utilisateurs
base_dn = "ou=equipe,dc=minet,dc=net"
# Filtre LDAP pour sélectionner les utilisateurs (potentiellement ajouter un filtre sur memberOf)
user_filter = "(objectClass=person)"
# Attributs LDAP à récupérer pour chaque utilisateur
attributes = ["uid", "sshPublicKey", "memberOf"]

[wireguard]
# Configuration de l'interface WireGuard
interface = "wg0"
# Chemin vers la clé privée du serveur WireGuard (doit exister et être lisible par l'utilisateur exécutant wg-ldap)
private_key_path = "/etc/wireguard/server_private.key"
# Adresse IP et CIDR de l'interface WireGuard
address = "10.8.0.1/16"
# Port UDP d'écoute de WireGuard
port = 51825

[nftables]
# Chemin vers le fichier de configuration nftables qui sera générée à chaque exécution de wg-ldap (doit être accessible en lecture/écriture par l'utilisateur exécutant wg-ldap)
output_path = "/etc/nftables.conf"
# Chemin vers un fichier de base nftables à inclure dans la configuration générée
base_path = "/etc/wg-ldap/nftables.base.conf"
# Liste des ports TCP autorisés en entrée (ce paramètre n'est utilisé que lors de la génération de la config avec gen-nft-base)
input_allow_tcp = [22]
# Liste des ports UDP autorisés en entrée (ce paramètre n'est utilisé que lors de la génération de la config avec gen-nft-base)
input_allow_udp = [51825]


[web]
# Host/port pour le petit serveur web de lookup (utilisé par wg-ldap-lookup)
host = "10.8.0.1"
# Port d'écoute du serveur web
port = 80
# Addresse IP publique ou hostname du serveur VPN, utilisé dans les configs clients générées
external_vpn_ip = "1.1.1.1"


# Routage par groupes
[per_group_routes]
# Typiquement le DN complet du groupe LDAP comme clé, et une liste de CIDR autorisés comme valeur
"cn=cluster-dev,ou=groups,dc=minet,dc=net" = ["192.168.103.0/24"]
"cn=cluster-prod,ou=groups,dc=minet,dc=net" = ["192.168.102.0/24", "10.8.0.0/16"]

# DNS par groupes
[per_group_dns]
# Typiquement le DN complet du groupe LDAP comme clé, et l'adresse IP du serveur DNS comme valeur
# Les requêtes DNS arrivant sur 10.8.0.1 (wireguard.address) seront redirigées vers le DNS du dernier groupe qui match
"*" = "8.8.8.8"
"cn=cluster-dev,ou=groups,dc=minet,dc=net" = "192.168.103.55"
"cn=cluster-prod,ou=groups,dc=minet,dc=net" = "192.168.102.55"
"""


def write_example_config(path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(EXAMPLE_CONFIG, encoding="utf-8")
