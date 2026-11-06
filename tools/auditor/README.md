# OpenGDS Auditor (gdsaudit)

Free Part 12 test tool. Results are a self-test, not OPC Foundation certification.
Layout follows the Auditor plan; this commit holds the seed code from the 2 Nov demo,
brought under the rules in `docs/architecture.md`.

| Path | Contents |
| --- | --- |
| `core/` | X.509 helpers, test CA (`TEST` subjects, 30-day validity), OPC UA client helpers with checked results |
| `selftest/` | Known-good targets: `push_test_server`, `pull_test_client`, and `run_demo.sh` (CTest `selftest_demo_flow`) |
| `profile_server/` | `push_driver`: plays the GDS CertificateManager against a push server (seed of the server profile) |
| `profile_client/` | `mock_gds`: plays a minimal GDS for pull clients, loopback only by default (seed of the client profile) |
| `profile_gds/` | OpenGDS T0 spec test programs (week 1) |

Build:

```sh
scripts/build_openssl.sh "$HOME/.cache/openssl"         # pinned OpenSSL 3.5.9, static
OPENSSL_ROOT="$HOME/.cache/openssl" \
  scripts/build_open62541.sh "$HOME/.cache/open62541"   # pinned v1.5.10, hardened
cmake -S . -B build -G Ninja -DOPEN62541_PREFIX="$HOME/.cache/open62541" \
  -DOPENSSL_ROOT_DIR="$HOME/.cache/openssl"
cmake --build build && ctest --test-dir build --output-on-failure
```
