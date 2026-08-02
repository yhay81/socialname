# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG RUST_IMAGE=rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
ARG RUNTIME_IMAGE=debian:bookworm-20260623-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

FROM ${RUST_IMAGE} AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/desktop/src-tauri ./apps/desktop/src-tauri
COPY vendor ./vendor
RUN cargo build --locked --release -p socialname-worker --bin socialname-worker

FROM ${RUNTIME_IMAGE} AS runtime

ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="SocialName managed worker" \
      org.opencontainers.image.description="Signed-rule-only one-shot managed probe worker" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/yhay81/socialname" \
      org.opencontainers.image.revision="${VCS_REF}"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/target/release/socialname-worker /usr/local/bin/socialname-worker
COPY --chown=10001:10001 rules/sites /opt/socialname/rules/sites

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /opt/socialname
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/socialname-worker"]
CMD ["--help"]
