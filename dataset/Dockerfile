FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        make \
        ninja-build \
        perl \
        pkg-config \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/pip3 /usr/local/bin/pip

WORKDIR /src
COPY openssl /src/openssl
COPY oqs-provider /src/oqs-provider

WORKDIR /src/openssl

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

RUN cd /src/oqs-provider \
        && OPENSSL_INSTALL=/opt/openssl-4.0.0 \
             LIBOQS_BRANCH=0.15.0 \
             PIP_BREAK_SYSTEM_PACKAGES=1 \
             OQSPROV_CMAKE_PARAMS="-DBUILD_TESTING=OFF" \
             bash scripts/fullbuild.sh -f \
        && cmake --install _build \
        && if [ -d /opt/openssl-4.0.0/lib64/ossl-modules ]; then \
                 mkdir -p /opt/openssl-4.0.0/lib; \
                 ln -sfn ../lib64/ossl-modules /opt/openssl-4.0.0/lib/ossl-modules; \
             elif [ -d /opt/openssl-4.0.0/lib/ossl-modules ]; then \
                 mkdir -p /opt/openssl-4.0.0/lib64; \
                 ln -sfn ../lib/ossl-modules /opt/openssl-4.0.0/lib64/ossl-modules; \
             else \
                 echo "ERROR: OpenSSL modules path not found after oqsprovider install." >&2; \
                 exit 1; \
             fi \
        && OPENSSL_MODULES=/opt/openssl-4.0.0/lib64/ossl-modules \
             /opt/openssl-4.0.0/bin/openssl list -providers \
                 -provider default \
                 -provider oqsprovider

ENV PATH="/opt/openssl-4.0.0/bin:${PATH}"
ENV OPENSSL_MODULES="/opt/openssl-4.0.0/lib64/ossl-modules"

WORKDIR /workspace