# syntax=docker/dockerfile:1.6
# linux/amd64 manifests pinned on 2026-08-24. The published image is currently
# amd64-only; update both digests deliberately when refreshing either base.
#
# Builder version is taken from rust-toolchain.toml (currently 1.99.0). The two
# must stay in sync.
FROM rust:1.99-slim-bookworm@sha256:452176c0cefca88c0b3184ce85a4eb03e3d4fa05d2afb5366abcba853221019e AS builder
WORKDIR /src

COPY . .
RUN cargo build --release --locked --bin rust-proxmoxmcp

# Create the directory tree with the right modes and ownership, since distroless
# has no shell and cannot run groupadd/useradd/install. The distroless :nonroot
# variant already ships uid 65532, so we create the tree with explicit modes and
# then COPY it.
#
# COPY preserves source modes: 0750 for config dirs, 0700 for state.
RUN install -d -m 0750 -o 65532 -g 65532 /stage-etc/proxmoxmcp \
    && install -d -m 0700 -o 65532 -g 65532 /stage-etc/proxmoxmcp/secrets \
    && install -d -m 0700 -o 65532 -g 65532 /stage-var/lib/proxmoxmcp

# Runtime base: distroless. Possible because this server has zero Command::new
# call sites in production code (grep confirms tests-only). The server makes
# outbound HTTPS calls but does not shell out, so it needs no shell or utilities.
#
# glibc rule: builder generation must be <= runtime generation. The builder is
# bookworm (glibc 2.36) and this is debian13 (glibc 2.41), so the direction is
# safe. Moving the builder forward would require moving this first.
#
# Digest resolved on 2026-08-24 from gcr.io/distroless/cc-debian13:nonroot.
# This is newer than the 2026-08-07 digest junos/mist share; they should be
# updated to this digest to avoid drift.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
LABEL org.opencontainers.image.source="https://github.com/mechubsec/rustproxmoxmcp"
LABEL org.opencontainers.image.licenses="MIT"

# CA certificates are shipped in gcr.io/distroless/cc-* at /etc/ssl/certs. The
# binary makes outbound TLS calls (HTTPS to Proxmox API and SSDF endpoint), and
# rustls uses the system CA bundle via rustls-native-certs.
COPY --from=builder --chown=65532:65532 \
    /src/target/release/rust-proxmoxmcp /usr/local/bin/rust-proxmoxmcp
COPY --from=builder --chown=65532:65532 /stage-etc/proxmoxmcp /etc/proxmoxmcp
COPY --from=builder --chown=65532:65532 /stage-var/lib/proxmoxmcp /var/lib/proxmoxmcp

ENV RUST_LOG=info
VOLUME ["/var/lib/proxmoxmcp"]
USER 65532:65532

# HEALTHCHECK removed: distroless has no shell and no `kill` utility. Container
# orchestrators (Compose healthcheck, Kubernetes liveness probes) supervise the
# process directly via the container runtime rather than shelling out.

# ENTRYPOINT carries what must always hold: config paths and anything security-
# relevant. CMD carries only what an operator is expected to replace: bind
# address, port, and mode flags. Docker replaces CMD when the caller supplies
# arguments, so security-relevant defaults must stay in ENTRYPOINT.
#
# --audit-hmac-key-file: this image is distroless with no shell, so a
# shell-script key-generation wrapper (as LXC's install.sh uses) can never
# run here. Instead the binary itself generates
# /var/lib/proxmoxmcp/audit-hmac.key on first run if it is absent (see
# ensure_audit_hmac_key in src/main.rs) -- the container-image equivalent of
# install.sh's own key-generation step, closing the "5 of 6 server images
# run unkeyed audit" gap (mecmcp#376 / MEC-978). The path is under the
# writable /var/lib/proxmoxmcp volume, not /etc/proxmoxmcp, which is mounted
# read-only in every documented `docker run` example. --audit-redact still
# defaults to empty (redaction itself stays opt-in), so this alone does not
# change what is logged -- it only means the key is already there the
# moment an operator turns redaction on.
ENTRYPOINT ["/usr/local/bin/rust-proxmoxmcp", \
    "--clusters-file", "/etc/proxmoxmcp/clusters.json", \
    "--tokens-file", "/var/lib/proxmoxmcp/tokens.json", \
    "--audit-hmac-key-file", "/var/lib/proxmoxmcp/audit-hmac.key"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30031"]
