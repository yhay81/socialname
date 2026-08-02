# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Builds the API server together with the monitoring console it serves on its
# own origin. The console is a static bundle that talks only to /v1 on the
# same origin, so hosting it here adds no CORS origin and no second
# authentication path.

ARG RUST_IMAGE=rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
ARG NODE_IMAGE=node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d
ARG RUNTIME_IMAGE=debian:bookworm-20260623-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

FROM ${RUST_IMAGE} AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/desktop/src-tauri ./apps/desktop/src-tauri
COPY vendor ./vendor
RUN cargo build --locked --release -p socialname-server --bin socialname-server

FROM ${NODE_IMAGE} AS console

WORKDIR /console
COPY apps/console/package.json apps/console/package-lock.json ./
RUN npm ci
COPY apps/console ./
RUN npm run build

FROM ${RUNTIME_IMAGE} AS runtime

ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="SocialName API server" \
      org.opencontainers.image.description="Versioned API server with the same-origin monitoring console" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/yhay81/socialname" \
      org.opencontainers.image.revision="${VCS_REF}"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/target/release/socialname-server /usr/local/bin/socialname-server
COPY --from=console --chown=10001:10001 /console/dist /opt/socialname/console

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SOCIALNAME_CONSOLE_DIR=/opt/socialname/console \
    SOCIALNAME_SERVER_BIND=0.0.0.0:8080

WORKDIR /opt/socialname
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/socialname-server"]
