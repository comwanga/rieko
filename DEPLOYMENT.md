# Rieko Deployment Guide

This document covers secure production deployment of the `rieko serve` API server.

## TLS / Transport Security

Rieko connects to LND over its REST API. **All production deployments must use TLS.**

### Why this matters

LND macaroons are bearer tokens — any party that intercepts a plain-text HTTP
connection can replay them indefinitely. Rieko enforces HTTPS by default and will
refuse to start a live-node scan or monitor cycle over `http://`.

### Override for local regtest / signet only

```bash
rieko scan --lnd-rest http://127.0.0.1:8080 --allow-insecure --network regtest ...
rieko monitor --lnd-rest http://127.0.0.1:8080 --allow-insecure --network regtest ...
```

**Never use `--allow-insecure` on mainnet or with real macaroons.**

---

## Running behind a reverse proxy

`rieko serve` binds to `127.0.0.1:3030` by default. When exposed through a
reverse proxy (nginx, Caddy, Traefik, etc.) that terminates TLS, pass
`--behind-proxy` so Rieko reads the real client IP from `X-Forwarded-For`:

```bash
rieko serve --behind-proxy --db /var/lib/rieko/rieko.db
```

### Example nginx configuration

```nginx
server {
    listen 443 ssl;
    server_name rieko.example.com;

    ssl_certificate     /etc/ssl/rieko.crt;
    ssl_certificate_key /etc/ssl/rieko.key;

    location / {
        proxy_pass         http://127.0.0.1:3030;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `LND_REST` | For live scans | LND REST base URL, e.g. `https://localhost:8080` |
| `LND_MACAROON` | For live scans | Path to admin macaroon file |
| `LND_TLS_CERT` | For self-signed TLS | Path to LND TLS certificate |
| `TELEGRAM_BOT_TOKEN` | Optional | Telegram alert bot token |
| `TELEGRAM_CHAT_ID` | Optional | Telegram chat ID for alerts |
| `OPENAI_API_KEY` | Optional | API key for LLM explanations |
| `OPENAI_BASE_URL` | Optional | Override base URL for compatible LLMs |

---

## Database

Rieko uses SQLite. The database path is set with `--db`:

```bash
rieko serve --db /var/lib/rieko/rieko.db
```

Migrations run automatically on startup. Back up the database before upgrading.

### Schema version history

| Version | Change |
|---|---|
| V13 | Webhook delivery deduplication table |
| V14 | `recommendations.lifecycle` column for resolved-finding cascades |

---

## Systemd unit example

```ini
[Unit]
Description=Rieko LND operational intelligence server
After=network.target

[Service]
Type=simple
User=rieko
EnvironmentFile=/etc/rieko/env
ExecStart=/usr/local/bin/rieko serve --db /var/lib/rieko/rieko.db --behind-proxy
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

---

## Security checklist

- [ ] LND REST endpoint uses `https://` (no `--allow-insecure` on mainnet)
- [ ] Macaroon file has restrictive permissions (`chmod 600`)
- [ ] `rieko serve` is not exposed directly on a public port — use a reverse proxy
- [ ] Pass `--behind-proxy` when behind nginx/Caddy/Traefik
- [ ] Telegram bot token stored outside version control (use env file or secret manager)
- [ ] Database file is backed up before schema-version upgrades
