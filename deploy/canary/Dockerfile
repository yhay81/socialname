# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Regional canary runner.
#
# Carries the CLI, the exact site-rule pack, and the reviewed canary manifests
# so a run measures the same rules the pack publishes. The image is inert by
# default: its entrypoint prints help and exits, and a canary only executes
# when a caller explicitly supplies the run command together with
# `--allow-live`.

ARG RUST_IMAGE=rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
ARG RUNTIME_IMAGE=debian:bookworm-20260623-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

FROM ${RUST_IMAGE} AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/desktop/src-tauri ./apps/desktop/src-tauri
COPY vendor ./vendor
# The application core embeds the published pack at build time, so the rules
# must be present before the binary is compiled, not only in the runtime stage.
COPY rules ./rules
RUN cargo build --locked --release -p socialname-cli --bin socialname

FROM ${RUNTIME_IMAGE} AS runtime

ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="SocialName canary runner" \
      org.opencontainers.image.description="Bounded regional canary execution against the published rule pack" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/yhay81/socialname" \
      org.opencontainers.image.revision="${VCS_REF}"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/target/release/socialname /usr/local/bin/socialname
COPY --chown=10001:10001 rules/sites /opt/socialname/rules/sites
COPY --chown=10001:10001 rules/canaries /opt/socialname/rules/canaries

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /opt/socialname
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/socialname"]
CMD ["--help"]
