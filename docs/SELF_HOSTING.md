# Self-hosting the Simplus sync server

`simplus-sync-server` is a single binary with a single SQLite file. It stores only encrypted data (see [SYNC_PROTOCOL.md](SYNC_PROTOCOL.md)), so a small VPS, a home server or a NAS is enough.

The app refuses plain `http://` for any host other than the local machine. **Put the server behind TLS.** The setups below do this with Caddy, which obtains certificates automatically.

## Option A: Docker Compose + Caddy (recommended)

1. Point a DNS name (for example `sync.example.com`) at the machine and open ports 80 and 443.
2. Edit `deploy/Caddyfile` and replace `sync.example.com` with your name.
3. From the repository root:

   ```sh
   docker compose -f deploy/docker-compose.yml up -d --build
   ```

4. In the app, open **Vault settings → Sync** and enter `https://sync.example.com`.

Data lives in the `simplus-data` volume (`/data/simplus-sync.db` inside the container).

To build only the image: `docker build -f server/simplus-sync-server/Dockerfile -t simplus-sync-server .`

## Option B: plain binary

```sh
cargo build --release -p simplus-sync-server
sudo install target/release/simplus-sync-server /usr/local/bin/
sudo useradd --system --home /var/lib/simplus --create-home simplus
sudo install -m 644 deploy/simplus-sync.toml /etc/simplus-sync.toml        # edit it
sudo install -m 644 deploy/simplus-sync.service /etc/systemd/system/
sudo systemctl enable --now simplus-sync
```

Then put a reverse proxy with TLS in front of `127.0.0.1:8080`. For Caddy that is:

```
sync.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

## Configuration

The configuration comes from a TOML file (`--config FILE` or `SIMPLUS_CONFIG`). Environment variables override the file. `deploy/simplus-sync.toml` documents every key.

| Setting | Env override | Default |
|---|---|---|
| `bind` | `SIMPLUS_BIND` | `0.0.0.0:8080` |
| `database` | `SIMPLUS_DATABASE` | `data/simplus-sync.db` |
| `registration` (`open`/`invite`/`closed`) | `SIMPLUS_REGISTRATION` | `open` |
| `trust_proxy` (use `X-Forwarded-For`) | `SIMPLUS_TRUST_PROXY` | `false` |
| `max_items_per_account`, `max_blob_bytes`, `max_body_bytes` | | 50 000 / 256 KiB / 16 MiB |
| `session_ttl_days` | | 90 |
| `auth_requests_per_minute` (per client IP) | | 30 |
| `lockout_threshold`, `lockout_minutes` | | 10 / 15 |

Check the effective configuration with `simplus-sync-server config`.

Only enable `trust_proxy` when the server is reachable *exclusively* through your proxy. Otherwise clients could fake their IP address and get around rate limiting.

## Administration

```sh
simplus-sync-server invite create --uses 5 --days 14   # for registration = "invite"
simplus-sync-server user list
simplus-sync-server user disable alice@example.com    # also signs out her devices
simplus-sync-server user enable alice@example.com
simplus-sync-server user delete alice@example.com --yes
simplus-sync-server stats
simplus-sync-server backup /backups/simplus-$(date +%F).db
```

With Docker, prefix the commands with `docker compose -f deploy/docker-compose.yml exec simplus-sync`.

## Backups and upgrades

- `backup` writes a consistent copy while the server keeps running (`VACUUM INTO`). Schedule it daily and keep copies off the machine. The backups contain only ciphertext, but treat them as sensitive anyway.
- To restore, stop the server and put the backup file in place of the database.
- To upgrade, replace the binary or image and restart. Database migrations run automatically on start.

## Security checklist

- TLS in front of the server, which listens on `127.0.0.1` or inside the Docker network.
- `registration = "invite"` or `"closed"` on a server reachable from the internet, unless you want open sign-up.
- Regular off-site backups.
- Keep the server updated.
- `GET /health` returns `ok`; use it for uptime monitoring.
