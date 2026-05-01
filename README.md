# wg-ldap - résumé rapide

Petit utilitaire pour synchroniser des peers WireGuard à partir d'un annuaire LDAP et générer une configuration nftables.

Commandes principales

- `wg-ldap`
  - Usage principal pour synchroniser et générer :
    - `uv run wg-ldap -- sync --config /etc/wg-ldap/config.toml` : récupère les utilisateurs LDAP, attribue des IPs et écrit les fichiers de config (WireGuard + nftables).
    - `uv run wg-ldap -- sync --apply` : idem + applique les configs (`wg syncconf` et `nft -f`).
    - `uv run wg-ldap -- generate` : génère les fichiers sans persister l'état ni appliquer.
    - `uv run wg-ldap -- init-config` : écrit un exemple de config dans `/etc/wg-ldap/config.toml`.

- `wg-ldap-web`
  - Petit serveur HTTP local qui répond `GET /<username>` avec l'IP attribuée (plain text). Utile pour vérifications rapides.
  - Démarrer : `uv run wg-ldap-web` (lit le `state_file` défini dans la config).

- `gen-nft-base` (via `wg-ldap gen-nft-base`)
  - Génère un fichier `nftables.base.conf` pour les interfaces données et l'écrit dans `nftables.base_path` défini dans la config.

Notes rapides

- Les chemins et options sont définis dans le fichier TOML de configuration (`/etc/wg-ldap/config.toml` par défaut).
- `uv run <script>` est utilisé pour lancer les scripts sans installation système.

## Comment ajouter sa clé ?

1. Générer une clé privée et publique WireGuard :
   ```bash
    wg genkey | tee privatekey | wg pubkey > publickey
   ```
2. Ajouter un utilisateur dans LDAP avec les attributs :
   - `uid`: nom d'utilisateur (ex: `alice`)
   - `sshdPublicKey`: contenu de `publickey`

3. Lancer la synchronisation pour que `wg-ldap` récupère les utilisateurs et génère les configs :
   ```bash
    uv run wg-ldap -- sync --apply
   ```
4. Vérifier que l'utilisateur a une IP attribuée :
   ```bash
    uv run wg-ldap-web
    curl http://localhost:8080/alice  # devrait retourner l'IP attribuée à alice
   ```
   En pratique, beaucoup de ces étapes peuvent être automatisées avec des services systemd. La partie génération de la config wireguard côté client et récupération de l'addresse IP peuvent être faites très facilement depuis la page du serveur web.
