# One image per service binary:
#   docker build --build-arg BIN=quorum_node    -t ciphersettle/quorum_node .
#   docker build --build-arg BIN=quorum_service -t ciphersettle/quorum_service .
#   docker build --build-arg BIN=quorum_notary  -t ciphersettle/quorum_notary .
# Gap 10. STATUS: policy-checked statically (ci/check_dockerfile.sh); NOT yet built
# or scanned (no Docker daemon/registry in the authoring sandbox) -> UNVERIFIED.
# Runtime image: distroless "cc" (glibc + libgcc only; no shell, no package manager),
# running as the image's built-in non-root user. Config, keys and shares are NEVER
# baked in: mount them read-only at run time (see deploy/README.md).
FROM rust:1.97-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
ARG BIN
RUN test -n "$BIN" && cargo build --release --locked -p "$BIN"

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
ARG BIN
COPY --from=build /src/target/release/${BIN} /app/service
USER 65532:65532
WORKDIR /app
ENTRYPOINT ["/app/service"]
