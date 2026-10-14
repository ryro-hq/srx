# Both image arguments require immutable references supplied by the caller.
ARG RUST_IMAGE
ARG BASE_IMAGE
FROM ${RUST_IMAGE} AS rust

# Build the setpriv version required by namespace and ioctl gates.
FROM ${BASE_IMAGE} AS setpriv
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libcap-ng-dev \
        pkg-config \
        xz-utils \
    && curl --fail --location \
        https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.42/util-linux-2.42.tar.xz \
        -o /tmp/util-linux.tar.xz \
    && printf '%s  /tmp/util-linux.tar.xz\n' \
        3452b260bbaa775d6e749ac3bb22111785003fc1f444970025c8da26dfa758e9 \
        | sha256sum -c - \
    && mkdir /tmp/util-linux \
    && tar -xJf /tmp/util-linux.tar.xz --strip-components=1 -C /tmp/util-linux \
    && cd /tmp/util-linux \
    && ./configure \
        --disable-all-programs \
        --enable-setpriv \
        --disable-nls \
        --without-python \
    && make -j2 setpriv \
    && ./setpriv --help | grep ioctl-dev

# The guest boots systemd and supplies native build and namespace tools.
FROM ${BASE_IMAGE}
ARG TEST_UID=1000
ARG TEST_GID=1000
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        bison \
        bubblewrap \
        build-essential \
        ca-certificates \
        curl \
        dbus-user-session \
        git \
        gawk \
        gnupg \
        liblzma-dev \
        libssl-dev \
        musl-tools \
        pkg-config \
        procps \
        python3 \
        systemd \
        systemd-sysv \
        util-linux \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=setpriv /tmp/util-linux/setpriv /usr/bin/setpriv

# Pinned editor tools are used only by the explicit ecosystem route.
RUN curl --fail --location \
        https://nodejs.org/dist/v26.10.0/node-v26.10.0-linux-x64.tar.xz \
        -o /tmp/node.tar.xz \
    && printf '%s  /tmp/node.tar.xz\n' \
        ca70e9e349de048b9522abb3adc05b3bd6f43c5ffd3ec57916c7da292f59f022 \
        | sha256sum -c - \
    && mkdir /opt/node \
    && tar -xJf /tmp/node.tar.xz --strip-components=1 -C /opt/node \
    && curl --fail --location \
        https://github.com/neovim/neovim/releases/download/v0.11.5/nvim-linux-x86_64.tar.gz \
        -o /tmp/nvim.tar.gz \
    && printf '%s  /tmp/nvim.tar.gz\n' \
        b2f91117be5b5ea39edd7297156dc2a4a8df4add6c95a90809a8df19e7ab6f52 \
        | sha256sum -c - \
    && mkdir /opt/nvim \
    && tar -xzf /tmp/nvim.tar.gz --strip-components=1 -C /opt/nvim \
    && /opt/node/bin/node --version | grep -Fx v26.10.0 \
    && /opt/nvim/bin/nvim --version | head -1 | grep -Fx 'NVIM v0.11.5' \
    && rm /tmp/node.tar.xz /tmp/nvim.tar.gz

COPY --from=rust /usr/local/rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu /opt/rust
RUN /opt/rust/bin/rustc --version | grep 'rustc 1.98.1 ' \
    && groupadd --gid ${TEST_GID} syrox \
    && useradd --uid ${TEST_UID} --gid ${TEST_GID} --create-home syrox \
    && mkdir -p /var/lib/systemd/linger \
    && touch /var/lib/systemd/linger/syrox \
    && mkdir -p /etc/systemd/system/user@.service.d \
    && printf '[Service]\nDelegate=yes\n' \
        > /etc/systemd/system/user@.service.d/syrox-test.conf

ENV PATH=/opt/node/bin:/opt/nvim/bin:/opt/rust/bin:/usr/bin:/bin
ENTRYPOINT ["/usr/lib/systemd/systemd"]
