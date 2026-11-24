# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS web-builder
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@10.6.1 --activate
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/tsconfig.json web/vite.config.ts web/index.html web/assets.d.ts ./web/
COPY web/apps ./web/apps
COPY web/packages ./web/packages
RUN pnpm --dir web install --frozen-lockfile && pnpm --dir web run build

FROM rust:1.99.1-bookworm AS rust-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY schema ./schema
COPY crates ./crates
COPY programs ./programs
RUN cargo build --release --locked --bin grdr --bin grdr-daemon --bin grdr-hook --bin grdr-server

FROM debian:bookworm-slim AS server
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 65532 grdrsrv && useradd --uid 65532 --gid 65532 --home-dir /var/lib/grdr --shell /usr/sbin/nologin grdrsrv
COPY --from=rust-builder /src/target/release/grdr-server /usr/local/bin/grdr-server
COPY --from=web-builder /src/web/dist /opt/grdr/web
RUN mkdir -p /var/lib/grdr && chown -R 65532:65532 /var/lib/grdr /opt/grdr/web
USER 65532:65532
WORKDIR /var/lib/grdr
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/grdr-server"]

FROM debian:bookworm-slim AS endpoint
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python3 && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 grdrqa && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/grdrqa --shell /bin/bash grdrqa
COPY --from=rust-builder /src/target/release/grdr /usr/local/bin/grdr
COPY --from=rust-builder /src/target/release/grdr-daemon /usr/local/bin/grdr-daemon
COPY --from=rust-builder /src/target/release/grdr-hook /usr/local/bin/grdr-hook
COPY .github/install-smoke/fixtures/claude-settings.json /opt/grdr/qa/claude-settings.json
COPY deploy/qa/run-slice0-e2e.sh /opt/grdr/qa/run-slice0-e2e.sh
RUN sed -i 's/\r$//' /opt/grdr/qa/run-slice0-e2e.sh && chmod 0755 /opt/grdr/qa/run-slice0-e2e.sh && chmod 0644 /opt/grdr/qa/claude-settings.json
USER 10001:10001
WORKDIR /home/grdrqa
ENTRYPOINT ["/bin/bash", "/opt/grdr/qa/run-slice0-e2e.sh"]
