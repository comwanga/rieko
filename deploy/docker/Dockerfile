FROM node:22-bookworm-slim AS frontend-builder

WORKDIR /source/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM rust:1.86-bookworm AS rust-builder

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY --from=frontend-builder /source/frontend/dist ./frontend/dist/
RUN cargo build --locked --release -p rieko-cli --bin rieko-agent

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates passwd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 rieko \
    && useradd --uid 10001 --gid rieko --home-dir /var/lib/rieko \
        --shell /usr/sbin/nologin rieko \
    && install -d -o rieko -g rieko -m 0700 /var/lib/rieko

COPY --from=rust-builder /source/target/release/rieko-agent /usr/local/bin/rieko-agent

USER 10001:10001
WORKDIR /var/lib/rieko
ENTRYPOINT ["/usr/local/bin/rieko-agent"]
