FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        make \
        perl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/openssl
COPY . /src/openssl

RUN arch="$(uname -m)" \
    && case "$arch" in \
        x86_64|amd64) target="linux-x86_64" ;; \
        aarch64|arm64) target="linux-aarch64" ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac \
    && ./Configure "$target" \
        --prefix=/opt/openssl-4.0.0 \
        --openssldir=/opt/openssl-4.0.0/ssl \
        no-asm \
        shared \
    && make clean \
    && make -j"$(nproc)" \
    && make install_sw \
    && mkdir -p /opt/openssl-4.0.0/ssl \
    && cp apps/openssl.cnf /opt/openssl-4.0.0/ssl/openssl.cnf \
    && printf '%s\n%s\n' /opt/openssl-4.0.0/lib64 /opt/openssl-4.0.0/lib > /etc/ld.so.conf.d/openssl-4.0.0.conf \
    && ldconfig \
    && /opt/openssl-4.0.0/bin/openssl version -a

ENV PATH="/opt/openssl-4.0.0/bin:${PATH}"

WORKDIR /workspace