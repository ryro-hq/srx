# Context: the libkrunfw source at the SDK v0.7.3 gitlink revision,
# cf4c22b9f05c680928e6d96a9d198f5845573a87, with Landlock enabled in
# config-libkrunfw_x86_64 and added to CONFIG_LSM. Only the guest is changed.
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS builder
# Upstream libkrunfw uses its own bin2cbundle tool to package kernel/initrd ELF.
# This is a build dependency of that pinned third-party firmware, not a Syrox runner.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential flex bison libelf-dev bc python3-pyelftools curl \
    ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /fw
COPY . .
RUN test "$(sed -n 's/^KERNEL_VERSION = //p' Makefile)" = linux-6.12.109 \
    && grep -qx CONFIG_SECURITY_LANDLOCK=y config-libkrunfw_x86_64 \
    && mkdir -p tarballs \
    && curl --fail --location --retry 3 https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.109.tar.gz -o tarballs/linux-6.12.109.tar.gz \
    && printf 'e81af28f5941db1c7f356151dfbab2ca5786c8be76474f7d42ea306cdeb445cd  tarballs/linux-6.12.109.tar.gz\n' | sha256sum -c - \
    && make -j4 \
    && grep -qx CONFIG_SECURITY_LANDLOCK=y linux-6.12.109/.config
FROM scratch
COPY --from=builder /fw/libkrunfw.so.5.6.1 /
COPY --from=builder /fw/linux-6.12.109/.config /kernel.config
