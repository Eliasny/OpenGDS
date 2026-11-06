# OpenGDS container image: opengdsd, opengds-signer and gdsadm on a
# distroless base. Non-root, runs with a read-only root filesystem.
# SPDX-License-Identifier: MPL-2.0
#
#   docker build -f packaging/docker/Dockerfile -t opengds .
#
# One image, two containers (docs/architecture.md, "Containers"): the signer
# holds the CA key and listens on a socket in a shared volume; opengdsd
# reaches it through `signer_socket`. packaging/docker/compose.yaml runs both,
# and docs/packaging.md explains the volumes and the passphrase secret.
#
# Users (numeric; distroless has no useradd):
#   10001:10001  opengds     opengdsd; owns /var/lib/opengds (group-readable)
#   10002:10001  opengds-ca  opengds-signer; owns /var/lib/opengds-signer and
#                            /run/opengds; group 10001 lets it read the store
#                            and lets opengdsd open the 0660 socket
#
# Reproducible: base images are pinned by digest, Debian packages come from a
# snapshot.debian.org date, and the release workflow passes SOURCE_DATE_EPOCH
# with BuildKit's rewrite-timestamp so layer times are the commit time.

ARG BUILD_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1

FROM ${BUILD_IMAGE} AS build
# Debian packages at a fixed date: the same Dockerfile installs the same
# compiler and libraries. snapshot.debian.org is slow under load: retry.
ARG DEBIAN_SNAPSHOT=20261101T000000Z
# (An empty DEBIAN_SNAPSHOT keeps the base image's own sources.)
RUN if [ -n "$DEBIAN_SNAPSHOT" ]; then \
        rm -f /etc/apt/sources.list.d/debian.sources && \
        printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' \
            "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list; \
    fi && \
    printf 'Acquire::Retries "10";\nAcquire::http::Timeout "60";\n' > /etc/apt/apt.conf.d/80-retries && \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git curl ca-certificates perl python3 \
        libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*
ARG SOURCE_DATE_EPOCH
WORKDIR /usr/src/opengds
COPY . .
RUN scripts/build_openssl.sh /opt/openssl /tmp/openssl-src && \
    OPENSSL_ROOT=/opt/openssl scripts/build_open62541.sh /opt/open62541 && \
    cmake -S . -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENGDS_BUILD_AUDITOR=OFF \
        -DCMAKE_C_FLAGS="-ffile-prefix-map=/tmp/build=/usr/src/opengds/build" \
        -DOPEN62541_PREFIX=/opt/open62541 -DOPENSSL_ROOT_DIR=/opt/openssl && \
    cmake --build /tmp/build && \
    ctest --test-dir /tmp/build --output-on-failure && \
    DESTDIR=/out cmake --install /tmp/build --prefix /usr --component opengds --strip
# The runtime base has glibc but not SQLite: take the library from the same
# snapshot, with its copyright file.
RUN multiarch=$(gcc -print-multiarch) && \
    install -d /out/usr/lib/$multiarch /out/usr/share/doc/libsqlite3-0 && \
    cp -L /usr/lib/$multiarch/libsqlite3.so.0 /out/usr/lib/$multiarch/ && \
    cp /usr/share/doc/libsqlite3-0/copyright /out/usr/share/doc/libsqlite3-0/ && \
    rm -rf /out/usr/lib/systemd /out/usr/lib/sysusers.d && \
    install -d -m 0750 /state/var/lib/opengds && \
    install -d -m 0700 /state/var/lib/opengds-signer && \
    install -d -m 0750 /state/run/opengds && \
    chown 10001:10001 /state/var/lib/opengds && \
    chown 10002:10001 /state/var/lib/opengds-signer /state/run/opengds

FROM ${RUNTIME_IMAGE}
LABEL org.opencontainers.image.title="OpenGDS" \
      org.opencontainers.image.description="OPC UA Global Discovery Server (OPC 10000-12)" \
      org.opencontainers.image.source="https://github.com/Eliasny/OpenGDS" \
      org.opencontainers.image.licenses="MPL-2.0"
COPY --from=build /out/ /
COPY --from=build /state/ /
USER 10001:10001
EXPOSE 58810
VOLUME ["/var/lib/opengds", "/var/lib/opengds-signer", "/run/opengds"]
ENTRYPOINT ["/usr/bin/opengdsd", "--config", "/etc/opengds/opengds.conf"]
