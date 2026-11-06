#!/usr/bin/env python3
# SPDX 2.3 (JSON) software bill of materials for one OpenGDS release artifact.
# SPDX-License-Identifier: MPL-2.0
#
# Called by scripts/release/build-release.sh. Lists what the artifact is built
# from and what it needs at run time:
#   - the OpenGDS source at the release commit
#   - statically linked: OpenSSL (pinned in scripts/build_openssl.sh) and
#     open62541 (pinned in scripts/build_open62541.sh) with the patches carried
#     in docs/upstream/patches/ and its git submodules
#   - dynamically linked: glibc and SQLite, at the versions of the build system
# Deterministic: the same inputs give the same bytes (time = SOURCE_DATE_EPOCH,
# document namespace derived from the artifact's SHA-256).
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

REPO_URL = "https://github.com/Eliasny/OpenGDS"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pinned(script, *names):
    """Read NAME=value lines from one of the pinned build scripts."""
    with open(script, encoding="utf-8") as f:
        text = f.read()
    out = []
    for n in names:
        m = re.search(r"^%s=(\S+)$" % n, text, re.M)
        if not m:
            sys.exit("sbom.py: %s not found in %s" % (n, script))
        out.append(m.group(1))
    return out


def run(cmd):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def system_version(fmt, deb_name, rpm_name):
    if fmt == "DEB":
        return run(["dpkg-query", "-W", "-f=${Version}", deb_name])
    return run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", rpm_name])


def spdx_id(name):
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--format", choices=["DEB", "RPM"], required=True)
    ap.add_argument("--openssl-prefix", required=True)
    ap.add_argument("--open62541-prefix", required=True)
    a = ap.parse_args()

    src = a.source
    art = os.path.basename(a.artifact)
    art_sha = sha256_file(a.artifact)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    name = "gdsaudit" if art.startswith("gdsaudit") else "opengds"
    # The artifact's own run-time requirements decide which system libraries
    # are listed (a .tar.gz carries every component, so it lists them all).
    if art.endswith(".deb"):
        requires = run(["dpkg-deb", "-f", a.artifact, "Depends"]) or ""
    elif art.endswith(".rpm"):
        requires = run(["rpm", "-qpR", a.artifact]) or ""
    else:
        requires = "sqlite"

    ossl_ver, ossl_sha = pinned(os.path.join(src, "scripts/build_openssl.sh"), "VERSION", "SHA256")
    o6_tag, o6_commit = pinned(os.path.join(src, "scripts/build_open62541.sh"), "TAG", "COMMIT")

    packages = []
    rels = []

    def add(pkg, rel_type, target_of=None):
        packages.append(pkg)
        if rel_type:
            rels.append({"spdxElementId": target_of or spdx_id("artifact"),
                         "relationshipType": rel_type,
                         "relatedSpdxElement": pkg["SPDXID"]})

    add({
        "SPDXID": spdx_id("artifact"),
        "name": name,
        "versionInfo": a.version,
        "packageFileName": art,
        "downloadLocation": "%s/releases/tag/v%s" % (REPO_URL, a.version),
        "checksums": [{"algorithm": "SHA256", "checksumValue": art_sha}],
        "licenseConcluded": "MPL-2.0",
        "licenseDeclared": "MPL-2.0",
        "copyrightText": "NOASSERTION",
        "supplier": "Organization: OpenGDS project",
        "primaryPackagePurpose": "APPLICATION",
        "filesAnalyzed": False,
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": "pkg:github/Eliasny/OpenGDS@v%s" % a.version}],
    }, None)
    rels.insert(0, {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": spdx_id("artifact")})

    add({
        "SPDXID": spdx_id("opengds-source"),
        "name": "OpenGDS source",
        "versionInfo": a.commit,
        "downloadLocation": "git+%s@%s" % (REPO_URL, a.commit),
        "licenseConcluded": "MPL-2.0",
        "licenseDeclared": "MPL-2.0",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "SOURCE",
        "filesAnalyzed": False,
    }, "GENERATED_FROM")

    add({
        "SPDXID": spdx_id("openssl"),
        "name": "openssl",
        "versionInfo": ossl_ver,
        "downloadLocation": "https://github.com/openssl/openssl/releases/download/openssl-%s/openssl-%s.tar.gz" % (ossl_ver, ossl_ver),
        "checksums": [{"algorithm": "SHA256", "checksumValue": ossl_sha}],
        "licenseConcluded": "Apache-2.0",
        "licenseDeclared": "Apache-2.0",
        "copyrightText": "NOASSERTION",
        "supplier": "Organization: OpenSSL Foundation",
        "primaryPackagePurpose": "LIBRARY",
        "filesAnalyzed": False,
        "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
             "referenceLocator": "pkg:generic/openssl@%s" % ossl_ver},
            {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
             "referenceLocator": "cpe:2.3:a:openssl:openssl:%s:*:*:*:*:*:*:*" % ossl_ver}],
    }, "STATIC_LINK")

    patch_dir = os.path.join(src, "docs/upstream/patches", o6_tag)
    patches = sorted(p for p in os.listdir(patch_dir) if p.endswith(".patch")) if os.path.isdir(patch_dir) else []
    patch_note = "; ".join("%s sha256:%s" % (p, sha256_file(os.path.join(patch_dir, p))) for p in patches)
    o6 = {
        "SPDXID": spdx_id("open62541"),
        "name": "open62541",
        "versionInfo": o6_tag + ("+opengds-patches" if patches else ""),
        "downloadLocation": "git+https://github.com/open62541/open62541.git@%s" % o6_commit,
        "licenseConcluded": "MPL-2.0",
        "licenseDeclared": "MPL-2.0",
        "copyrightText": "NOASSERTION",
        "supplier": "Organization: open62541",
        "primaryPackagePurpose": "LIBRARY",
        "filesAnalyzed": False,
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": "pkg:github/open62541/open62541@%s" % o6_tag}],
    }
    if patches:
        o6["comment"] = "Built from %s with the OpenGDS patches %s" % (o6_commit, patch_note)
    add(o6, "STATIC_LINK")

    # open62541's submodules that end up in the library, at the commits the
    # pinned tag records. ua-nodeset supplies the compiled-in GDS model; the
    # others count only when the feature that builds them is on.
    o6_src = os.path.join(a.open62541_prefix, "src/open62541")
    try:
        with open(os.path.join(a.open62541_prefix, "include/open62541/config.h"), encoding="utf-8") as f:
            o6_config = f.read()
    except OSError:
        sys.exit("sbom.py: open62541 config.h not found under %s" % a.open62541_prefix)
    linked = {"ua-nodeset": True}
    for sub, feature in (("mdnsd", "UA_ENABLE_DISCOVERY_MULTICAST_MDNSD"), ("mqtt-c", "UA_ENABLE_MQTT"),
                         ("nodesetLoader", "UA_ENABLE_NODESETLOADER")):
        linked[sub] = re.search(r"^#define %s\b" % feature, o6_config, re.M) is not None
    subs = run(["git", "-C", o6_src, "submodule", "status"]) or ""
    for line in subs.splitlines():
        parts = line.strip().lstrip("+-U").split()
        if len(parts) < 2:
            continue
        sub_commit, sub_path = parts[0], parts[1]
        if not linked.get(os.path.basename(sub_path), False):
            continue
        url = run(["git", "-C", o6_src, "config", "-f", ".gitmodules", "--get",
                   "submodule.%s.url" % sub_path]) or "NOASSERTION"
        pkg = {
            "SPDXID": spdx_id("open62541-" + os.path.basename(sub_path)),
            "name": os.path.basename(sub_path),
            "versionInfo": sub_commit,
            "downloadLocation": ("git+%s@%s" % (url, sub_commit)) if url != "NOASSERTION" else url,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
            "comment": "git submodule %s of open62541 %s" % (sub_path, o6_tag),
        }
        packages.append(pkg)
        rels.append({"spdxElementId": spdx_id("open62541"), "relationshipType": "CONTAINS",
                     "relatedSpdxElement": pkg["SPDXID"]})

    for pname, deb, rpm, lic in (("glibc", "libc6", "glibc", "LGPL-2.1-or-later"),
                                 ("sqlite", "libsqlite3-0", "sqlite-libs", "blessing")):
        if pname == "sqlite" and "sqlite" not in requires:
            continue
        ver = system_version(a.format, deb, rpm) or "NOASSERTION"
        add({
            "SPDXID": spdx_id(pname),
            "name": deb if a.format == "DEB" else rpm,
            "versionInfo": ver,
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": lic,
            "licenseDeclared": lic,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "filesAnalyzed": False,
            "comment": "Run-time dependency from the distribution; version of the build system",
        }, "DYNAMIC_LINK")

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": art,
        "documentNamespace": "%s/sbom/%s-%s" % (REPO_URL, art, art_sha),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: opengds-sbom.py", "Organization: OpenGDS project"],
        },
        "packages": packages,
        "relationships": rels,
    }
    json.dump(doc, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
