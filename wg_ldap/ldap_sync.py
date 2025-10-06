from __future__ import annotations

import logging
from typing import Iterable, List

import ldap
import ldap.ldapobject

from .config import LDAPConfig
from .ipam import LDAPUser


log = logging.getLogger(__name__)

WG_PUBKEY_SIZE = 44  # Base64-encoded size of a WireGuard public key


class LDAPClient:
    def __init__(self, config: LDAPConfig) -> None:
        self.cfg = config

    def _connect(self) -> ldap.ldapobject.SimpleLDAPObject:
        log.debug("Connecting to LDAP at %s", self.cfg.url)
        conn = ldap.initialize(str(self.cfg.url))
        log.debug("Binding as %s", self.cfg.bind_dn)
        conn.simple_bind_s(self.cfg.bind_dn, self.cfg.password)
        return conn

    def get_users(self, limit: int | None = None) -> List[LDAPUser]:
        log.debug(
            "Searching LDAP base_dn=%s filter=%s attrs=%s",
            self.cfg.base_dn,
            self.cfg.user_filter,
            self.cfg.attributes,
        )
        conn = self._connect()
        try:
            results = conn.search_s(
                self.cfg.base_dn,
                ldap.SCOPE_SUBTREE,  # type: ignore[attr-defined]
                self.cfg.user_filter,
                self.cfg.attributes,
            )
        finally:
            conn.unbind_s()

        if results is None:
            results = []
        log.debug("LDAP returned %d entries", len(results))
        users: List[LDAPUser] = []
        for dn, entry in results: # pyright: ignore[reportAssignmentType]
            if not entry:
                continue
            uid_b = entry.get("uid", [None])[0]
            if not uid_b:
                continue
            pub_b = entry.get("sshPublicKey", None)
            if not pub_b:
                continue
            for pub_b in entry.get("sshPublicKey", [None]):
                if pub_b and isinstance(pub_b, (bytes, bytearray)) and len(pub_b) == WG_PUBKEY_SIZE:
                    break
            else:
                continue # no valid public key found

            uid = uid_b.decode() if isinstance(uid_b, (bytes, bytearray)) else str(uid_b)
            public_key = pub_b.decode() if isinstance(pub_b, (bytes, bytearray)) else str(pub_b)
            groups_raw = entry.get("memberOf", [])
            groups = [
                (g.decode() if isinstance(g, (bytes, bytearray)) else str(g)) for g in groups_raw
            ]
            users.append(LDAPUser(uid=uid, public_key=public_key, groups=groups))
            if limit and len(users) >= limit:
                break

        log.debug("Parsed %d users from LDAP", len(users))
        return users
