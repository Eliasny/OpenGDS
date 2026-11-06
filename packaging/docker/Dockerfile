# OpenGDS container image: opengdsd + opengds-signer + gdsadm.
#   docker build -f packaging/docker/Dockerfile -t opengds .
#   docker run -p 58810:58810 -v opengds:/var/lib/opengds \
#       -v ./etc:/etc/opengds:ro opengds
# /etc/opengds holds opengds.conf, users and ca-passphrase (mode 0600, owned
# by uid 10001). The passphrase is read by opengds-signer from the file only.
# SPDX-License-Identifier: MPL-2.0
FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git curl ca-certificates perl python3 \
        libsqlite3-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN scripts/build_openssl.sh /opt/openssl /tmp/ossl && \
    OPENSSL_ROOT=/opt/openssl scripts/build_open62541.sh /opt/open62541 && \
    cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENGDS_BUILD_AUDITOR=OFF \
        -DOPEN62541_PREFIX=/opt/open62541 -DOPENSSL_ROOT_DIR=/opt/openssl && \
    cmake --build /build && ctest --test-dir /build --output-on-failure

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-0 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 10001 --home-dir /var/lib/opengds opengds && \
    install -d -m 0700 -o opengds -g opengds /var/lib/opengds /var/lib/opengds-signer
COPY --from=build /build/src/daemon/opengdsd /build/src/daemon/gdsadm /usr/bin/
COPY --from=build /build/src/signer/opengds-signer /usr/libexec/opengds/opengds-signer
USER opengds
EXPOSE 58810
VOLUME ["/var/lib/opengds", "/var/lib/opengds-signer"]
ENTRYPOINT ["/usr/bin/opengdsd", "--config", "/etc/opengds/opengds.conf"]
