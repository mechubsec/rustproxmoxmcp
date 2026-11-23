# syntax=docker/dockerfile:1.6
# Multi-arch image index digests pinned on 2026-08-24; the release builds
# linux/amd64 and linux/arm64 from them. Update both deliberately when
# refreshing either base.
#
# Builder version is taken from rust-toolchain.toml (currently 1.100.0). The two
# must stay in sync.
# Source of libgcc-s1 only; the runtime is base-nossl, which lacks it. Not the
# runtime itself, so keep it ahead of the builder and out of the last FROM.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS libgcc

FROM rust:1.100-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS builder
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

# libgcc_s.so.1 is the one library the binary needs beyond glibc, and
# base-nossl does not ship it. Stage it with its dpkg records (status.d) so
# Trivy and the SBOM still see libgcc-s1 and gcc-14-base. The multiarch
# directory is taken from the builder's own triplet (x86_64 or aarch64).
COPY --from=libgcc / /cc/
RUN triplet="$(gcc -dumpmachine | sed 's/-pc-/-/')" \
    && install -d "/stage-libgcc/usr/lib/${triplet}" /stage-libgcc/var/lib/dpkg/status.d \
    && cp -a "/cc/usr/lib/${triplet}/libgcc_s.so.1" "/stage-libgcc/usr/lib/${triplet}/" \
    && cp -a /cc/var/lib/dpkg/status.d/libgcc-s1 /cc/var/lib/dpkg/status.d/libgcc-s1.md5sums \
        /cc/var/lib/dpkg/status.d/gcc-14-base /cc/var/lib/dpkg/status.d/gcc-14-base.md5sums \
        /stage-libgcc/var/lib/dpkg/status.d/

# Runtime base: distroless base-nossl (no libssl3t64/libcrypto: the binary is
# rustls-only, and libssl3t64 carries unfixed CVE-2026-124709). Possible because
# this server has zero Command::new call sites in production code, so it needs
# no shell or utilities.
#
# glibc rule: builder generation must be <= runtime generation. The builder is
# bookworm (glibc 2.36) and this is debian13 (glibc 2.41), so the direction is
# safe. Moving the builder forward would require moving this first.
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:4006ac92504be607b70de01d1f64f38288c69fcd8faa820f6d3aed266ea32ac5
LABEL org.opencontainers.image.source="https://github.com/mechubsec/rustproxmoxmcp"
LABEL org.opencontainers.image.licenses="MIT"
# Official MCP Registry ownership check: must equal server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/rustproxmoxmcp"

# CA certificates are shipped in gcr.io/distroless/base-nossl-* at /etc/ssl/certs. The
# binary makes outbound TLS calls (HTTPS to Proxmox API and SSDF endpoint), and
# rustls uses the system CA bundle via rustls-native-certs.
COPY --from=builder /stage-libgcc/ /
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
