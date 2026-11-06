#!/bin/sh
# Installs the opengds .deb on a systemd host (the Ubuntu 24.04 CI runner),
# brings up the signer socket and opengdsd under their real sandboxes, and
# checks that the GDS got its own certificate through the signer unit.
# Then removes the package and checks the CA key was kept.
# Usage: scripts/release/smoke-test-systemd.sh <opengds .deb>
# Needs root (sudo) and a running systemd. Changes the host: CI runners only.
# SPDX-License-Identifier: MPL-2.0
set -eu
DEB=${1:?usage: smoke-test-systemd.sh <opengds .deb>}
[ -d /run/systemd/system ] || { echo "smoke-test-systemd.sh: needs systemd" >&2; exit 1; }
URI=urn:smoke-test:opengds
STORE=/var/lib/opengds/opengds.db

fail() {
    echo "smoke test FAILED: $1"
    sudo systemctl --no-pager status opengds-signer.socket opengds.service 'opengds-signer@*' || true
    sudo journalctl --no-pager -u opengds.service -u 'opengds-signer@*' -u opengds-signer.socket | tail -60 || true
    exit 1
}

sudo apt-get install -y "$(realpath "$DEB")"
id opengds && id opengds-ca || fail "system users not created"
[ "$(stat -c '%U:%G %a' /etc/opengds)" = "root:opengds 750" ] || fail "/etc/opengds owner or mode"

# Users file, configuration and the CA passphrase credential (docs/packaging.md)
cred=$(printf '%s' "smoke-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" | gdsadm hash-password)
printf 'admin DiscoveryAdmin,CertificateAuthorityAdmin,SecurityAdmin %s\n' "$cred" |
    sudo install -m 0640 -o root -g opengds /dev/stdin /etc/opengds/users
sed -e "s|^application_uri = .*|application_uri = $URI|" -e 's|^hostname = .*|hostname = localhost|' \
    /usr/share/doc/opengds/opengds.conf.example |
    sudo install -m 0640 -o root -g opengds /dev/stdin /etc/opengds/opengds.conf
printf '%s' "ca-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" |
    sudo systemd-creds encrypt --name=ca-passphrase - /etc/opengds/ca-passphrase.cred

sudo systemctl enable --now opengds-signer.socket opengds.service || fail "units did not start"

# opengdsd listens once it has its own certificate, which only the signer can issue.
i=0
until ss -ltnH 'sport = :58810' | grep -q LISTEN; do
    i=$((i + 1))
    [ "$i" -le 60 ] || fail "opengdsd not listening on 58810 after 60 s"
    systemctl is-failed --quiet opengds.service && fail "opengds.service failed"
    sleep 1
done
sudo -u opengds gdsadm apps list --store "$STORE" | grep -q "$URI" || fail "the GDS did not register itself"
sudo -u opengds gdsadm certs status --store "$STORE" | grep -q "$URI" || fail "no certificate for the GDS"
sudo test -s /var/lib/opengds-signer/ca/ca.der || fail "no CA certificate in the signer's state"
[ "$(sudo stat -c '%U %a' /var/lib/opengds-signer)" = "opengds-ca 700" ] || fail "signer state owner or mode"
[ "$(stat -c '%U:%G %a' /run/opengds/signer.sock)" = "opengds-ca:opengds 660" ] || fail "signer socket owner or mode"

# The sandbox as systemd applies it (the offline check runs in ctest).
sudo systemd-analyze security --no-pager opengds.service | tail -1
sudo systemctl restart opengds.service || fail "restart"
sleep 3
systemctl is-active --quiet opengds.service || fail "not active after restart"

sudo apt-get remove -y opengds
systemctl list-unit-files 'opengds*' --no-legend | grep -q . && fail "units left after remove"
sudo test -s /var/lib/opengds-signer/ca/ca.der || fail "remove deleted the CA"
echo "smoke test passed"
