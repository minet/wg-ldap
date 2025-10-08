# wg-ldap — résumé rapide

Petit utilitaire pour synchroniser des peers WireGuard à partir d'un annuaire LDAP et générer une configuration nftables.

Commandes principales

- wg-ldap

  - Usage principal pour synchroniser et générer :
    - `uv run wg-ldap -- sync --config /etc/wg-ldap/config.toml` : récupère les utilisateurs LDAP, attribue des IPs et écrit les fichiers de config (WireGuard + nftables).
    - `uv run wg-ldap -- sync --apply` : idem + applique les configs (`wg syncconf` et `nft -f`).
    - `uv run wg-ldap -- generate` : génère les fichiers sans persister l'état ni appliquer.
    - `uv run wg-ldap -- init-config` : écrit un exemple de config dans `/etc/wg-ldap/config.toml`.

- wg-ldap-lookup

  - Petit serveur HTTP local qui répond `GET /<username>` avec l'IP attribuée (plain text). Utile pour vérifications rapides.
  - Démarrer : `uv run wg-ldap-lookup` (lit le `state_file` défini dans la config).

- gen-nft-base (via `wg-ldap gen-nft-base`)
  - Génère un fichier `nftables.base.conf` pour les interfaces données et l'écrit dans `nftables.base_path` défini dans la config.

Notes rapides

- Les chemins et options sont définis dans le fichier TOML de configuration (`/etc/wg-ldap/config.toml` par défaut).
- `uv run <script>` est utilisé pour lancer les scripts sans installation système.

Pour plus de détails, voir `INSTALLATION.md` et les fichiers sous `wg_ldap/`.
