# Isolated native compiler support for the existing musl release contract.
ARG RUST_IMAGE=rust@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7
FROM ${RUST_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
ENV CC_x86_64_unknown_linux_musl=musl-gcc
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
