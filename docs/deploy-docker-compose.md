# Run `rieko-agent` as a Docker Compose sidecar

This example runs `rieko-agent` as a separate non-root service using only the
existing `--config`, `--db`, `--token-file`, `--addr`, and
`--allow-external` flags. It does not poll during setup or introduce container-
specific runtime configuration.

The Compose file publishes the authenticated API only on host loopback at
`127.0.0.1:8080`. Other containers on the Compose network can also reach the
service as `http://rieko-agent:8080`, but every request still requires the API
token.

## Prerequisites

- A Linux host with Docker Engine and the Docker Compose v2 plugin
- `curl` for downloading the deployment files and checking the API
- `sha256sum` and `tar` for verifying and extracting the operator CLI
- Root access or `sudo` for assigning the documented UID/GID and file modes

## Prepare a clean deployment directory

The agent source tree is not required. On a clean host, download only the
Compose file and non-secret configuration example from the repository:

```sh
mkdir -p rieko/config rieko/secrets
cd rieko
curl -fsSLo docker-compose.yml \
  https://raw.githubusercontent.com/comwanga/rieko/main/deploy/docker/docker-compose.yml
curl -fsSLo config/rieko.json \
  https://raw.githubusercontent.com/comwanga/rieko/main/deploy/docker/config/rieko.json.example
```

This produces:

```text
rieko/
|-- docker-compose.yml
|-- config/
|   `-- rieko.json                 UID 10001, mode 0400
`-- secrets/
    |-- api-token                  UID 10001, mode 0400
    `-- btcpay-greenfield.key      UID 10001, mode 0400

Docker volume: rieko-data          mounted at /var/lib/rieko
SQLite file:  rieko.db             created with non-root ownership
```

The real config and secret paths are excluded from the Docker build context.
Never add the two secret files to the Compose YAML or commit them to Git.

## Prepare config and secret mounts

Edit `config/rieko.json` with the BTCPay URL, store, network, and optional node.

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

Pull the published stable image and start it without a source build:

```sh
docker compose pull rieko-agent
docker compose up --no-build -d rieko-agent
docker compose ps
docker compose logs -f rieko-agent
```

The Compose file defaults to `ghcr.io/comwanga/rieko:v0.1.1`. Set
`RIEKO_AGENT_IMAGE` to another published tag or immutable digest when an
explicitly validated upgrade is required. The retained `build` section is for
repository development and CI; it is not used by this clean-host procedure.

## Install the operator CLI

The public container contains `rieko-agent`. Install the matching checksummed
`rieko` operator CLI from the same GitHub Release without a source checkout or
Rust toolchain:

```sh
RIEKO_VERSION=v0.1.1
RIEKO_ASSET="rieko-${RIEKO_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
RIEKO_RELEASE="https://github.com/comwanga/rieko/releases/download/${RIEKO_VERSION}"

curl -fLO "${RIEKO_RELEASE}/${RIEKO_ASSET}"
curl -fLO "${RIEKO_RELEASE}/${RIEKO_ASSET}.sha256"
sha256sum --check "${RIEKO_ASSET}.sha256"
tar -xzf "${RIEKO_ASSET}"
test "$(./rieko --version)" = "rieko 0.1.1"
sudo install -o root -g root -m 0755 rieko /usr/local/bin/rieko
rieko --version
```

The mounted API token is intentionally readable only by container UID 10001.
Create a separate protected host-client copy without exposing its value on the
command line:

```sh
install -d -m 0700 "${HOME}/.config/rieko"
sudo install -o "$(id -u)" -g "$(id -g)" -m 0400 \
  ./secrets/api-token "${HOME}/.config/rieko/api-token"
```

Update or remove that copy when rotating the mounted API token. Then run the
read-only operator commands against the loopback API:

```sh
rieko status --api-url http://127.0.0.1:8080 \
  --token-file "${HOME}/.config/rieko/api-token"
rieko inspect all --api-url http://127.0.0.1:8080 \
  --token-file "${HOME}/.config/rieko/api-token"
rieko doctor --api-url http://127.0.0.1:8080 \
  --token-file "${HOME}/.config/rieko/api-token"
```

Without a separately installed CLI, verify the authenticated API directly:

```sh
API_TOKEN="$(sudo cat ./secrets/api-token)"
curl --fail --header "Authorization: Bearer ${API_TOKEN}" \
  http://127.0.0.1:8080/status
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
