# Packages, container image and releases

OpenGDS ships as:

| Artifact | For | Contents |
|---|---|---|
| `opengds_<ver>-1~deb13_<arch>.deb`, `…~ubuntu24.04…` | Debian 13, Ubuntu 24.04 | server: `opengdsd`, `opengds-signer`, `gdsadm`, systemd units |
| `opengds-<ver>-1.el9.<arch>.rpm`, `…fc<N>…` | RHEL, Alma and Rocky 9; Fedora | the same |
| `gdsaudit_…deb`, `gdsaudit-…rpm` | the same distributions | the OpenGDS Auditor command-line tool |
| `opengds-<ver>-deb13-<arch>.tar.gz` | other glibc distributions | every component under `usr/` |
| `opengds-<ver>.tar.gz` | building from source | `git archive` of the release tag |
| `ghcr.io/eliasny/opengds:<ver>` | Docker, Podman, Kubernetes | server on a distroless base, amd64 and arm64 |

Architectures: amd64 (x86_64) and arm64 (aarch64). Each binary artifact has an SPDX 2.3 SBOM next to it (`<artifact>.spdx.json`).

OpenSSL 3.5 (decision G2) and open62541 v1.5.10 are linked statically, so the packages depend only on glibc, SQLite and systemd 252 or newer.

## Installed files

| Path | What |
|---|---|
| `/usr/bin/opengdsd` | the GDS server |
| `/usr/bin/gdsadm` | administration on the GDS host (reads the store read-only) |
| `/usr/libexec/opengds/opengds-signer` | the CA key holder (decision G1) |
| `/usr/lib/systemd/system/opengds.service` | `opengdsd`, user `opengds` |
| `/usr/lib/systemd/system/opengds-signer.socket`, `opengds-signer@.service` | the signer, user `opengds-ca`, started per `opengdsd` connection |
| `/usr/lib/sysusers.d/opengds.conf` | the `opengds` and `opengds-ca` system users |
| `/usr/share/doc/opengds/` | `opengds.conf.example`, `opengdsd.md`, this file, the license |

Created at run time, never shipped in a package:

| Path | Owner, mode | What |
|---|---|---|
| `/etc/opengds/` | `root:opengds 0750` | configuration (made by the package's post-install script) |
| `/var/lib/opengds/` | `opengds 0750` | the store and the GDS's own certificate (systemd `StateDirectory`) |
| `/var/lib/opengds-signer/` | `opengds-ca 0700` | the CA key and certificate |
| `/run/opengds/signer.sock` | `opengds-ca:opengds 0660` | the only way to reach the signer |

Removing or purging the package never deletes `/var/lib/opengds` or `/var/lib/opengds-signer`: they hold the CA key and every issued certificate.

## First start (systemd)

The package installs the units but does not enable them, because the server needs configuration first.

```sh
# 1. Users file (docs/opengdsd.md, "First start")
gdsadm hash-password            # reads the password from stdin
sudo install -m 0640 -o root -g opengds /dev/stdin /etc/opengds/users <<'EOF'
admin DiscoveryAdmin,CertificateAuthorityAdmin,SecurityAdmin <credential>
EOF

# 2. Configuration
sudo install -m 0640 -o root -g opengds /usr/share/doc/opengds/opengds.conf.example /etc/opengds/opengds.conf
sudoedit /etc/opengds/opengds.conf      # application_uri, hostname, organization

# 3. CA key passphrase as an encrypted credential: only opengds-signer@ gets it
sudo systemd-creds encrypt --name=ca-passphrase - /etc/opengds/ca-passphrase.cred

# 4. Start
sudo systemctl enable --now opengds-signer.socket opengds.service
journalctl -u opengds -u 'opengds-signer@*'
```

Both services run sandboxed: `packaging/tests/check_unit_exposure.sh` keeps each unit's `systemd-analyze security` exposure below 2.0 (docs/architecture.md, "Around the process"); CI fails otherwise.

## Container

One image runs as two containers: the signer, which alone gets the passphrase and the CA volume and has no network, and `opengdsd`. They share a socket volume, and the signer mounts the store read-only. `packaging/docker/compose.yaml` sets this up:

```sh
mkdir etc
# etc/opengds.conf from packaging/opengds.conf.example, with
#   signer_socket = /run/opengds/signer.sock   (and no `signer =` line)
# etc/users as above
printf '%s' 'the CA key passphrase' > ca-passphrase && chmod 0400 ca-passphrase
sudo chown 10001:10001 etc/* && sudo chmod 0640 etc/*
docker compose -f packaging/docker/compose.yaml up -d
```

Both containers run non-root (`opengds` 10001, `opengds-ca` 10002, shared group 10001), with a read-only root filesystem, all capabilities dropped and `no-new-privileges`. The base is `gcr.io/distroless/cc-debian13`: no shell, no package manager.

Build the image yourself with `docker build -f packaging/docker/Dockerfile -t opengds .`.

## Building packages

```sh
scripts/release/build-release.sh dist/          # on Debian, Ubuntu, EL or Fedora
```

It builds the pinned OpenSSL and open62541 when `OPENSSL_PREFIX` and `OPEN62541_PREFIX` are not set, configures a Release build, runs the tests, and writes the packages of the distribution it runs on, their SBOMs and `SHA256SUMS` into `dist/`. `WITH_TGZ=1` adds the plain archive, and `WITH_SOURCE=1` adds the source archive.

For a trial with uncommitted changes, set `ALLOW_DIRTY=1`. Release builds refuse a dirty tree, and refuse a `v*` tag that does not match the version in `CMakeLists.txt`.

## Reproducible builds

The same commit, built in the same pinned build container, gives byte-identical packages, archives and SBOMs:

- every timestamp is `SOURCE_DATE_EPOCH`, which is the commit time;
- source and build paths are mapped away (`-ffile-prefix-map`);
- locale, time zone and umask are fixed, and binaries are stripped;
- the RPM build host is `reproducible`, and its build time is the commit time.

`scripts/release/check-reproducible.sh <work-dir>` builds twice, from clones at different paths, and fails if any byte differs. The release workflow does the same on two separate runners from scratch, and publishes nothing if the two disagree.

The Debian and Ubuntu build containers are pinned by digest. The container image's build stage installs its packages from a fixed snapshot.debian.org date.

Signing adds bytes: an RPM carries its signature inside, so compare the unsigned payload with `rpm --delsign` before comparing hashes. The `.deb` and `.tar.gz` files are signed with detached signatures and stay byte-identical.

## SBOM

`scripts/release/sbom.py` writes one SPDX 2.3 JSON document per binary artifact. It lists:

- the OpenGDS source at the release commit;
- OpenSSL, with the version and the tarball SHA-256 pinned in `scripts/build_openssl.sh`;
- open62541, with the commit pinned in `scripts/build_open62541.sh`, the patches carried from `docs/upstream/patches/`, and the git submodules that are compiled in;
- glibc and SQLite, as dynamic dependencies, at the versions of the build system.

## Verifying a release

Every release file is signed twice (decision P1): with Sigstore keyless signing in the release workflow, and with the OpenGDS OpenPGP release key.

```sh
# Sigstore: proves the file came from the release workflow at that tag
cosign verify-blob opengds_0.1.0-1~deb13_amd64.deb \
  --bundle opengds_0.1.0-1~deb13_amd64.deb.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Eliasny/OpenGDS/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify opengds_0.1.0-1~deb13_amd64.deb --repo Eliasny/OpenGDS

# OpenPGP (key in docs/release-signing-key.asc, fingerprint in SECURITY.md)
gpg --import docs/release-signing-key.asc
gpg --verify SHA256SUMS.asc && sha256sum -c SHA256SUMS --ignore-missing
gpg --verify opengds_0.1.0-1~deb13_amd64.deb.asc
rpm --import docs/release-signing-key.asc && rpm -K opengds-0.1.0-1.el9.x86_64.rpm

# Container image
cosign verify ghcr.io/eliasny/opengds:0.1.0 \
  --certificate-identity-regexp '^https://github.com/Eliasny/OpenGDS/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Making a release

1. Set `project(OpenGDS VERSION x.y.z)` in `CMakeLists.txt` in a pull request.
2. After it merges, tag the merge commit: `git tag -s vx.y.z && git push origin vx.y.z`.
3. `.github/workflows/release.yml` builds every distribution and architecture twice, compares the builds, signs the files, pushes the image to ghcr.io and creates a draft GitHub release.
4. Check the draft and publish it.
