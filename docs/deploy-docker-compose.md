# Run `rieko-agent` as a Docker Compose sidecar

This example runs `rieko-agent` as a separate non-root service using only the
existing `--config`, `--db`, `--token-file`, `--addr`, and
`--allow-external` flags. It does not poll during setup or introduce container-
specific runtime configuration.

The Compose file publishes the authenticated API only on host loopback at
`127.0.0.1:8080`. Other containers on the Compose network can also reach the
service as `http://rieko-agent:8080`, but every request still requires the API
token.

## Files

The example lives under `deploy/docker`:

```text
deploy/docker/
|-- Dockerfile
|-- docker-compose.yml
|-- config/
|   |-- rieko.json.example
|   `-- rieko.json                 UID 10001, mode 0400, not committed
`-- secrets/
    |-- api-token                  UID 10001, mode 0400, not committed
    `-- btcpay-greenfield.key      UID 10001, mode 0400, not committed

Docker volume: rieko-data          mounted at /var/lib/rieko
SQLite file:  rieko.db             created with non-root ownership
```

The real config and secret paths are excluded from the Docker build context.
Never add the two secret files to the Compose YAML or commit them to Git.

## Prepare config and secret mounts

Copy the non-secret example and edit its URL, store, network, and optional node:

```sh
cd deploy/docker
cp config/rieko.json.example config/rieko.json
```

The key reference inside `config/rieko.json` must remain the container path:

```json
"api_key_file": "/run/secrets/btcpay-greenfield.key"
```

Create `secrets/api-token` and `secrets/btcpay-greenfield.key` as single-line
files using a protected editor or copy them from a protected source. Do not put
their contents on a command line. The BTCPay key should be scoped and read-only.

On Linux, make the bind-mounted files readable only by the container's fixed
non-root UID/GID `10001:10001`:

```sh
sudo chown -R 10001:10001 config secrets
sudo chmod 0750 config secrets
sudo chmod 0400 config/rieko.json
sudo chmod 0400 secrets/api-token
sudo chmod 0400 secrets/btcpay-greenfield.key
```

Docker Desktop handles bind-mount ownership through its file-sharing layer.
Keep the host files restricted to the account running Docker and verify that
they are not readable by other local users.

The named `rieko-data` volume is initialized from `/var/lib/rieko` in the image,
which is owned by UID/GID `10001:10001`. The container is read-only everywhere
except that persistent volume and a small in-memory `/tmp`.

## Start, inspect, and stop

Build and start the sidecar:

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f rieko-agent
```

Use the mounted API token with existing CLI read commands from the host:

```sh
rieko status --api-url http://127.0.0.1:8080 \
  --token-file ./secrets/api-token
rieko doctor --api-url http://127.0.0.1:8080 \
  --token-file ./secrets/api-token
```

Stop with the agent's existing graceful `SIGINT` path and keep SQLite data:

```sh
docker compose stop
docker compose down
```

`stop_grace_period: 30s` gives the existing bounded worker shutdown time to
finish. `restart: unless-stopped` restarts an unexpected exit but respects an
operator stop. To remove the persisted database intentionally, use
`docker compose down --volumes`; that command is destructive.

## Referencing backend endpoints

Inside a container, `localhost` means that container itself. Use one of these
forms instead:

- If BTCPay, Bitcoin Core, or LND is a service on the same Compose network, use
  its service name and container port, such as `http://btcpay:<port>`,
  `http://bitcoind:<rpc-port>`, or `https://lnd:<rest-port>`.
- If a backend runs on the Docker host, use
  `host.docker.internal:<published-port>`. The example includes the Linux
  `host-gateway` mapping; Docker Desktop provides the same hostname.
- If a backend is external, use its normal DNS name and TLS URL.

The checked-in config example demonstrates the BTCPay URL. Bitcoin Core and LND
remain configured with their existing `rieko-agent` command-line flags and
credential-file mounts when those observers are needed. Do not add container
auto-discovery or replace endpoint hosts with `localhost`.

For a sidecar attached to a different Compose project, connect `rieko-agent` to
that project's shared external network and use the backend service aliases on
that network. Keep the host API port bound to `127.0.0.1` unless a separately
secured deployment requires otherwise.

The resulting flow is:

```text
docker compose up
  -> rieko-agent --config /etc/rieko/rieko.json
  -> /var/lib/rieko/rieko.db on persistent rieko-data volume
  -> authenticated API on host 127.0.0.1:8080
```
