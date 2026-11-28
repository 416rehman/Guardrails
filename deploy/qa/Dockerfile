# syntax=docker/dockerfile:1

ARG NODE_IMAGE=docker.io/library/node:22-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb
ARG RUST_IMAGE=docker.io/library/rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c
ARG DEBIAN_IMAGE=docker.io/library/debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

FROM ${NODE_IMAGE} AS web-builder
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@10.6.1 --activate
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/tsconfig.json web/vite.config.ts web/index.html web/assets.d.ts ./web/
COPY web/apps ./web/apps
COPY web/packages ./web/packages
RUN pnpm --dir web install --frozen-lockfile --ignore-scripts && pnpm --dir web run build

FROM ${RUST_IMAGE} AS rust-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY contracts ./contracts
COPY crates ./crates
COPY programs ./programs
RUN cargo build --release --locked --bin grdr --bin grdr-daemon --bin grdr-engine --bin grdr-hook --bin grdr-uplink --bin grdr-server

FROM ${DEBIAN_IMAGE} AS server
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 65532 grdrsrv && useradd --uid 65532 --gid 65532 --home-dir /var/lib/grdr --shell /usr/sbin/nologin grdrsrv
COPY --from=rust-builder /src/target/release/grdr-server /usr/local/bin/grdr-server
COPY --from=web-builder /src/web/dist /opt/grdr/web
COPY --from=web-builder /src/web/dist-operator /opt/grdr/operator-web
RUN mkdir -p /var/lib/grdr && chown -R 65532:65532 /var/lib/grdr /opt/grdr/web /opt/grdr/operator-web
USER 65532:65532
WORKDIR /var/lib/grdr
EXPOSE 8787 44444
ENTRYPOINT ["/usr/local/bin/grdr-server"]

FROM ${DEBIAN_IMAGE} AS endpoint
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python3 && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 grdrqa && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/grdrqa --shell /bin/bash grdrqa
COPY --from=rust-builder /src/target/release/grdr /usr/local/bin/grdr
COPY --from=rust-builder /src/target/release/grdr-daemon /usr/local/bin/grdr-daemon
COPY --from=rust-builder /src/target/release/grdr-engine /usr/libexec/grdr/grdr-engine
COPY --from=rust-builder /src/target/release/grdr-hook /usr/local/bin/grdr-hook
COPY --from=rust-builder /src/target/release/grdr-uplink /usr/local/bin/grdr-uplink
COPY .github/install-smoke/fixtures/claude-settings.json /opt/grdr/qa/claude-settings.json
COPY deploy/qa/run-slice0-e2e.sh /opt/grdr/qa/run-slice0-e2e.sh
RUN sed -i 's/\r$//' /opt/grdr/qa/run-slice0-e2e.sh && chmod 0755 /opt/grdr/qa/run-slice0-e2e.sh /usr/libexec/grdr/grdr-engine && chmod 0644 /opt/grdr/qa/claude-settings.json
USER 10001:10001
WORKDIR /home/grdrqa
ENTRYPOINT ["/bin/bash", "/opt/grdr/qa/run-slice0-e2e.sh"]

FROM ${NODE_IMAGE} AS playwright-e2e
WORKDIR /src
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN corepack enable && corepack prepare pnpm@10.6.1 --activate
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/tsconfig.json web/playwright.config.ts ./web/
COPY web/e2e ./web/e2e
RUN pnpm --dir web install --frozen-lockfile --ignore-scripts \
    && pnpm --dir web exec playwright install chromium --with-deps \
    && chown -R 1000:1000 /src /opt/pw-browsers
USER 1000:1000
ENTRYPOINT ["pnpm", "--dir", "web", "run", "test:e2e"]
