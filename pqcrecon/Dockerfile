# PQCRecon Dockerfile
# Build context: project root (one level above pqcrecon/)
# Build with:   docker build -f pqcrecon/Dockerfile -t pqcrecon .

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# 1. System dependencies (iproute2 provides 'ip route' for interface detection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    iproute2 \
    make \
    ninja-build \
    perl \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# 2. Build OpenSSL 3.x + oqs-provider (from project-root submodules)
WORKDIR /src
COPY openssl /src/openssl
COPY oqs-provider /src/oqs-provider

WORKDIR /src/openssl
RUN arch="$(uname -m)" \
    && case "$arch" in \
    x86_64|amd64) target="linux-x86_64" ;; \
    aarch64|arm64) target="linux-aarch64" ;; \
    *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
    esac \
    && ./Configure "$target" \
    --prefix=/opt/openssl \
    --openssldir=/opt/openssl/ssl \
    no-asm shared \
    && make clean && make -j"$(nproc)" && make install_sw \
    && mkdir -p /opt/openssl/ssl \
    && cp apps/openssl.cnf /opt/openssl/ssl/openssl.cnf \
    && printf '%s\n%s\n' /opt/openssl/lib64 /opt/openssl/lib > /etc/ld.so.conf.d/openssl.conf \
    && ldconfig

WORKDIR /src/oqs-provider
RUN OPENSSL_INSTALL=/opt/openssl \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    OQSPROV_CMAKE_PARAMS="-DBUILD_TESTING=OFF" \
    bash scripts/fullbuild.sh -f \
    && cmake --install _build \
    && if [ -d /opt/openssl/lib64/ossl-modules ]; then \
    mkdir -p /opt/openssl/lib; \
    ln -sfn ../lib64/ossl-modules /opt/openssl/lib/ossl-modules; \
    elif [ -d /opt/openssl/lib/ossl-modules ]; then \
    mkdir -p /opt/openssl/lib64; \
    ln -sfn ../lib/ossl-modules /opt/openssl/lib64/ossl-modules; \
    fi

# 3. Copy project and install Python deps
WORKDIR /workspace
COPY classification /workspace/classification
COPY pqcrecon      /workspace/pqcrecon

RUN pip install --no-cache-dir --break-system-packages \
    rich \
    pyshark \
    joblib \
    scikit-learn \
    numpy

# 4. Environment
ENV PATH="/opt/openssl/bin:${PATH}"
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "pqcrecon/pqcrecon.py"]
