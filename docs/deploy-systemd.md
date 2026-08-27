# Run `rieko-agent` with systemd

This is a minimal production-style example for a native Linux deployment. It
uses the existing `rieko-agent` flags and the non-secret configuration written
by `rieko attach btcpay`. It does not add another configuration mechanism.

The example keeps the API on `127.0.0.1:8080`. Put an authenticated local
client or a separately secured reverse proxy in front of it if remote access is
required.

## Directory layout

```text
/usr/local/bin/rieko-agent                 root:root   0755
/etc/systemd/system/rieko-agent.service    root:root   0644
/etc/rieko/                                root:rieko  0750
|-- rieko.json                             root:rieko  0640
`-- secrets/                               root:rieko  0750
    |-- api-token                          root:rieko  0640
    `-- btcpay-greenfield.key              root:rieko  0640
/var/lib/rieko/                            rieko:rieko 0700
`-- rieko.db                               rieko:rieko 0600
```

The systemd unit is world-readable because service definitions normally are,
but only `root` may modify it. The config is restricted even though it contains
no secret values. The API token and BTCPay API key are separate files readable
only by `root` and the `rieko` group. `UMask=0077` ensures the agent creates its
SQLite files without group or world access.

## Create the service account and directories

Run these commands as an administrator:

```sh
sudo groupadd --system rieko
sudo useradd --system --gid rieko --home-dir /var/lib/rieko \
  --shell /usr/sbin/nologin rieko

sudo install -d -o root -g rieko -m 0750 /etc/rieko
sudo install -d -o root -g rieko -m 0750 /etc/rieko/secrets
sudo install -d -o rieko -g rieko -m 0700 /var/lib/rieko
sudo install -o root -g root -m 0755 target/release/rieko-agent \
  /usr/local/bin/rieko-agent
```

If the account or group already exists, verify its ownership rather than
creating it again.

## Install configuration and secrets

The configuration contains a path to the BTCPay key, never the key itself:

```json
{
  "version": 1,
  "btcpay": {
    "greenfield_base_url": "https://btcpay.example.com",
    "store_id": "your-store-id",
    "api_key_file": "/etc/rieko/secrets/btcpay-greenfield.key",
    "network": "mainnet",
    "node": "optional-stable-node-scope"
  }
}
```

Prepare that JSON and the two single-line secret files in a protected staging
location. Install them without putting secret values in the command line or
shell history:

```sh
sudo install -o root -g rieko -m 0640 /protected/path/rieko.json \
  /etc/rieko/rieko.json
sudo install -o root -g rieko -m 0640 /protected/path/api-token \
  /etc/rieko/secrets/api-token
sudo install -o root -g rieko -m 0640 /protected/path/btcpay-greenfield.key \
  /etc/rieko/secrets/btcpay-greenfield.key
```

Use a scoped, read-only Greenfield API key. The `api-token` protects Rieko's
local HTTP API; it is unrelated to the BTCPay key. Do not place either secret
inside `rieko.json`.

Verify the resulting access controls:

```sh
sudo chown root:rieko /etc/rieko/rieko.json
sudo chown root:rieko /etc/rieko/secrets/api-token
sudo chown root:rieko /etc/rieko/secrets/btcpay-greenfield.key
sudo chmod 0640 /etc/rieko/rieko.json
sudo chmod 0640 /etc/rieko/secrets/api-token
sudo chmod 0640 /etc/rieko/secrets/btcpay-greenfield.key
sudo chown rieko:rieko /var/lib/rieko
sudo chmod 0700 /var/lib/rieko
```

## Service unit

The repository includes [`deploy/systemd/rieko-agent.service`](../deploy/systemd/rieko-agent.service):

```ini
[Unit]
Description=Rieko Bitcoin infrastructure observability agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=rieko
Group=rieko
UMask=0077
ExecStart=/usr/local/bin/rieko-agent --config /etc/rieko/rieko.json --db /var/lib/rieko/rieko.db --token-file /etc/rieko/secrets/api-token --addr 127.0.0.1:8080
Restart=on-failure
RestartSec=5s
KillSignal=SIGINT
TimeoutStopSec=30s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rieko

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` restarts unexpected failures without creating a restart
loop after an intentional stop. `KillSignal=SIGINT` uses the agent's existing
graceful-shutdown path. The 30-second stop timeout leaves time for polling and
webhook workers to finish or be bounded by the runtime's shutdown limits.

Install the root-owned, non-writable service definition:

```sh
sudo install -o root -g root -m 0644 deploy/systemd/rieko-agent.service \
  /etc/systemd/system/rieko-agent.service
```

## Reload, start, inspect, and stop

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now rieko-agent.service
sudo systemctl status rieko-agent.service
sudo journalctl -u rieko-agent.service -f
```

After changing `rieko.json` or rotating a referenced secret file, restart the
service explicitly:

```sh
sudo systemctl restart rieko-agent.service
```

To exercise graceful shutdown or disable startup:

```sh
sudo systemctl stop rieko-agent.service
sudo systemctl disable rieko-agent.service
```

The resulting flow is:

```text
systemd
  -> rieko-agent --config /etc/rieko/rieko.json
  -> existing authenticated API and polling runtime
  -> /var/lib/rieko/rieko.db
```
