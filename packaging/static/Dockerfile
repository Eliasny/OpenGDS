# OpenGDS Auditor container image: the static gdsaudit on distroless/static.
# Non-root, nothing but the binary, its licences and CA-free /etc files.
# SPDX-License-Identifier: MPL-2.0
#
#   docker build -f packaging/static/Dockerfile -t gdsaudit .
#   docker run --rm -v "$PWD/w:/work" gdsaudit gds --url opc.tcp://gds:58810 \
#       --trust /work/gds-ca.der --user admin --password-file /work/admin.pw \
#       --work /work/auditor --report /work/results
#
# /work is the only writable place the Auditor needs: its identities, test
# PKI and reports. The image's user is 65532 (distroless nonroot), so the
# mounted folder must be writable by it. The client profile's fake GDS
# listens with --listen PORT --listen-any; publish that port.
#
# Reproducible: base images are pinned by digest, packaging/static/build.sh
# maps build paths away and takes its time stamps from SOURCE_DATE_EPOCH.

ARG BUILD_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

FROM ${BUILD_IMAGE} AS build
RUN printf 'Acquire::Retries "10";\nAcquire::http::Timeout "60";\n' > /etc/apt/apt.conf.d/80-retries && \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential musl-tools linux-libc-dev cmake ninja-build git curl \
        ca-certificates perl python3 && \
    rm -rf /var/lib/apt/lists/*
ARG SOURCE_DATE_EPOCH
WORKDIR /usr/src/opengds
COPY . .
RUN packaging/static/build.sh /out /opt/deps && \
    mkdir -p /image/work && \
    cp /out/gdsaudit-*-static/gdsaudit /image/gdsaudit && \
    cp -r /out/gdsaudit-*-static/licenses /image/licenses

FROM ${RUNTIME_IMAGE}
COPY --from=build /image/gdsaudit /usr/bin/gdsaudit
COPY --from=build /image/licenses /usr/share/doc/gdsaudit/
COPY --from=build --chown=65532:65532 /image/work /work
WORKDIR /work
USER 65532:65532
LABEL org.opencontainers.image.title="OpenGDS Auditor" \
      org.opencontainers.image.description="gdsaudit: OPC 10000-12 self-test tool (not OPC Foundation certification)" \
      org.opencontainers.image.source="https://github.com/Eliasny/OpenGDS" \
      org.opencontainers.image.licenses="MPL-2.0"
ENTRYPOINT ["/usr/bin/gdsaudit"]
