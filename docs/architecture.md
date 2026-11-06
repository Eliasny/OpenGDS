# OpenGDS secure C architecture

Status: proposal, 6 Nov 2026. Applies to OpenGDS (`opengdsd`, `libopengds`, `libgdsclient`, `gdsadm`, `gdsctl`), the OpenGDS Auditor (`tools/auditor/`) and the public plugin API that UASM builds on. It refines the OpenGDS plan (01) and the Auditor plan (03); where it changes them, the change is listed under [Changes to the plans](#changes-to-the-plans).

## Summary

OpenGDS is the most valuable target on a plant network: whoever controls it can mint identities for every OPC UA application. It is written in C (decided, for speed and footprint), and C gives no memory safety of its own. So the architecture assumes that some bug in our code, in open62541 or in OpenSSL will one day be exploitable, and makes sure that bug cannot reach the CA key or forge an issuance on its own.

Five ideas carry the design:

1. **Split by privilege.** The network-facing daemon never holds the CA private key. A small separate process, `opengds-signer`, owns the key and builds every certificate itself from the registered record. A fully compromised network process can only ask for signatures it is allowed to ask for, and every request is logged by the signer.
2. **Parse as little as possible, and only in proven parsers.** All OPC UA decoding is done by open62541, all ASN.1 and crypto by OpenSSL 3. Our own code works on decoded, type-checked, size-limited values. Every place where we do parse is fuzzed.
3. **One set of C rules, enforced by tools, not by memory.** A short coding standard derived from SEI CERT C and MISRA C:2023, where every rule names the compiler flag, analyser check or test that enforces it.
4. **Defence in depth at build and run time.** OpenSSF-recommended hardening flags, sanitizer and fuzzing CI, seccomp and Landlock in the process, systemd sandboxing around it.
5. **Secure by default, fail closed.** SignAndEncrypt only, no Anonymous, no trust on first use outside test tools, every limit set, and any internal error refuses the operation instead of degrading it.

The rest of this document gives the findings behind each choice, the rules, and the files that implement them.

## Findings

What the research found, and what each finding changes. Sources are listed at the end.

| # | Finding | Consequence for OpenGDS |
| --- | --- | --- |
| F1 | CISA and the FBI list "new product lines in a memory-unsafe language" and "no published memory-safety roadmap by 1 Jan 2026" among product security bad practices for critical infrastructure. They are guidance, not law, but customers and auditors read them. | Publish a memory-safety roadmap with 1.0 (`docs/memory-safety.md`): the containment described here, the measured fuzzing and sanitizer coverage, and the boundary at which a component would move to a memory-safe language (the signer is the first candidate, because it is small and has a narrow interface). C stays the language. |
| F2 | open62541 had several 2026 CVEs: an integer overflow in `UA_Variant` arrayDimensions (out-of-bounds write, CVSS 8.8), a use-after-free in TransferSubscriptions (8.1), a PubSub underflow, and denial-of-service bugs in FindServers and endpoint URL handling. The advisories list 1.5.0–1.5.4 as affected; v1.5.10 is the newest 1.5.x tag and the newest stable release. | Keep the exact pin on v1.5.10, and add a written rule: a newer 1.5.x patch release that fixes a security issue is adopted within 14 days as one reviewed commit that changes only the pin, after the full spec suite and fuzz corpus pass. Subscribe to the open62541 GitHub advisories and CISA ICS advisories. Turn off every library feature OpenGDS does not use (PubSub, historizing, MQTT). JSON and XML must stay on in v1.5.10: event filter parsing needs JSON, and without XML the generated GDS nodeset loses its Value attributes, so every method loses its InputArguments. |
| F3 | OpenSSL 3.0 LTS reached end of life on 7 Sep 2026. Ubuntu 24.04 still ships 3.0.13. OpenSSL 3.5 is the current LTS (to April 2030) and adds ML-DSA and ML-KEM; Argon2id is in OpenSSL since 3.2. | Minimum OpenSSL is 3.5. CI builds against 3.5 (Debian 13 ships it; other images build it from a pinned tarball with a checked hash). This also gives the Argon2id password hashing the plan needs without a second library, and ML-DSA for post-quantum agility. |
| F4 | The ANSSI/Inria formal analysis of OPC UA (USENIX Security 2025) found attacks on the secure channel that the 1.05.07 SecureChannelEnhancements close. open62541 v1.5.10 implements the flags. | Enable the enhancement flags and prefer ECC policies (decided in the plan). The Auditor's server profile checks that targets advertise them and warns otherwise. |
| F5 | Most real C vulnerabilities in parsers come from integer overflow in size calculations, missing length checks and lifetime bugs (CWE-787, 416, 125, 190 lead the 2025 CWE Top 25). | Checked-arithmetic helpers for every size computation, a hard limits table for every input, explicit ownership rules, and fuzzing for every function that takes bytes from the network. |
| F6 | The OpenSSF compiler hardening guide recommends a specific flag set (`_FORTIFY_SOURCE=3`, `-fstack-clash-protection`, `-fcf-protection`, `-ftrivial-auto-var-init`, `-fstrict-flex-arrays=3`, full RELRO, PIE and others), and GCC 14 bundles most of it as `-fhardened`. | `cmake/hardening.cmake` applies the full set to our code **and** to open62541 (the plan only hardened our own code). |
| F7 | Static analysers find different bugs: GCC `-fanalyzer` finds leaks and double frees in C, clang-tidy's `cert-*` and `bugprone-*` checks map to CERT C rules, CodeQL finds tainted-data paths, cppcheck has a MISRA addon. | All four run in CI. New findings fail the build; there is no baseline file to hide them in. |
| F8 | The EU Cyber Resilience Act's vulnerability reporting duties apply since 11 Sep 2026; PKI and certificate issuance software is an Annex III important product. | Security process from day one: SECURITY.md, private advisories, SBOM per release, signed and reproducible builds, a recorded triage of every sanitizer and fuzz crash. Same files serve UASM's CRA technical file. |
| F9 | Reviewing the demo code (the seed for the Auditor) showed the typical C problems: results of `malloc`/`realloc` not checked, method outputs dereferenced without checking type or array length, no upper bound on a trust list read loop, `atoi` for ports, errors of file writes ignored, global mutable state. Its security behaviour (SignAndEncrypt only, SecurityAdmin checks, no TOFU in the pull client) is right. | When the demo moves into `tools/auditor/` it is brought under these rules, with each fix covered by a test. Details in [Appendix A](#appendix-a-demo-code-review). |

## Threat model in one page

The full model lives in `docs/security-model.md` (W4). The architecture answers these attacker positions:

| Attacker | Can | Must not be able to |
| --- | --- | --- |
| Anyone on the network | Open TCP connections, send malformed messages, flood | Crash the daemon, exhaust memory, make it sign anything, learn which applications exist |
| A registered application (ApplicationSelfAdmin) | Call pull methods for its own record | Get a certificate with another ApplicationUri, renew someone else's certificate, read other records |
| A compromised admin client or stolen admin credential | Whatever that role allows | Act outside its role; erase the audit trail; get the CA key |
| Remote code execution in `opengdsd` | Everything the network process can do | Read the CA key, sign a certificate whose contents do not match a stored, approved record, rewrite the audit chain without detection, write outside the state directory, start a shell |
| A malicious target under test (Auditor) | Return hostile answers to the Auditor | Crash the Auditor, make it write outside its results folder, make it leave a live target in a broken state |
| A malicious plugin | Anything; plugins run with the privileges of the process that loads them | This is documented, not prevented. Plugins are trusted code; only root-owned files load |

## Process architecture

```
                 OPC UA (SignAndEncrypt)                       OPC UA
pull clients ─┐                                         ┌──► managed servers
admin clients ┼──► opengdsd  (user opengds, no key)  ───┘    (push engine)
              │     ├─ open62541 server thread (decode, dispatch, encode)
              │     ├─ worker pool (async methods, store, push)
              │     ├─ store (SQLite, WAL) ──► /var/lib/opengds/store
              │     └─ ca_ipc client ──┐  socketpair, fixed message schema
              │                         ▼
              │   opengds-signer (user opengds-ca, no network)
              │     ├─ re-checks record + policy, builds the certificate
              │     ├─ CA key: encrypted PKCS#8, OpenSSL provider (PKCS#11 HSM, TPM2)
              │     └─ own append-only issuance log ──► /var/lib/opengds-ca/
              └── gdsctl (offline, root, host only)
```

**opengdsd** is the daemon from the plan, with one change: the CA backend slot is filled by `ca_ipc.c`, which forwards to the signer. It runs as an unprivileged user, holds no long-term secret except its own application key, and after start-up applies a seccomp filter and a Landlock ruleset so it can only touch its state directory and sockets.

**opengds-signer** is a new, small executable (target: under 3,000 lines of our own code). It is started by systemd as its own unit with its own user, connected to `opengdsd` through a socket that only those two users can open. It:

- accepts exactly five requests: `SIGN_CSR`, `NEW_KEY_PAIR`, `REVOKE`, `ISSUE_CRL`, `GET_CHAIN`;
- reads the application record and the request's approval state from the store itself (read-only connection), instead of trusting what `opengdsd` sends, and refuses if the record does not exist, is not approved, or the CSR's public key is already in use by another application;
- builds every certificate field from the record (subject, SAN URI, DNS/IP, key usage, validity); nothing comes from the CSR except the public key;
- enforces rate limits per application and globally, so a compromised daemon cannot mass-produce certificates unnoticed;
- appends every operation to its own hash-chained log, in a directory `opengdsd` cannot write, which `gdsctl verify-audit` cross-checks against the daemon's audit log;
- loads the CA backend through the unchanged `ca.h` interface, so UASM's ceremony CA plugin and HSM profiles run inside the signer.

**Embedding and tests.** `libopengds` keeps an in-process CA option (`ca_mode = "inprocess"`) for unit tests, examples and small embedded devices. It logs a warning at start-up and is never the default for `opengdsd`.

**Why not threads or one process.** A thread shares the address space, so it protects nothing against memory corruption. The cost of the split is one IPC round trip per issuance (microseconds, against milliseconds of RSA signing) and one more systemd unit.

### Threads and ownership across them

- The open62541 server thread only decodes, dispatches and encodes. Method callbacks that do more than a lookup are async (`UA_Server_setAsyncCallMethodResult`) and run on the worker pool.
- **Async results are completed on the server thread** (docs/spikes/02). A worker never calls `UA_Server_setAsyncCallMethodResult` and never sees the output pointer: it posts its result to a queue that a server-thread callback drains. The upstream tutorial pattern (completing from the worker) deadlocks with the cancel callback in v1.5.10. The cancel callback runs under the server lock and takes no lock of ours. No lock of ours is held across any call into open62541.
- **Signing is not an async method call.** StartSigningRequest and StartNewKeyPairRequest validate and store the request (synchronous, about a millisecond), return the request id, and queue the signing or key generation as a background job to the signer. FinishRequest reads the store. A disconnect loses nothing and no call ties up a session while the signer works. Async method calls stay for calls that must answer with a slow result, such as push work on a managed server.
- Bounds: `maxAsyncOperationQueueSize` 256 (a full worker queue refuses with `Bad_TooManyOperations`), `asyncOperationTimeout` 30 s (clients are told to wait longer), event `queueSizeLimits.max` 10000 so pending approval dialogs survive a ConditionRefresh (docs/spikes/01), and a configured cap on pending approvals.
- Shutdown order: stop the server loop and join its thread, stop and join the workers, run the completion callback once on the deleting thread, then `UA_Server_delete`.
- A job handed to the worker pool **owns** its input: the server thread deep-copies the method arguments into the job (`UA_copy`) and never touches them again. The worker frees them. No pointer into open62541's request buffers crosses a thread.
- Shared state is one of: immutable after start, owned by one thread and reached by message, or protected by a single named mutex with a documented lock order (`docs/locking.md`). No lock is held across a call into a plugin, OpenSSL, the store or the network.
- Reference-counted buffers (encoded trust lists) use C11 atomics and are immutable once published.
- TSan runs the integration tests on every push, with `tsan.supp` holding the two lock-order reports inside open62541 v1.5.10 (`UA_Timer_add`, `UA_Timer_process`) that cannot deadlock because the event loop mutex gates them. The file names the open62541 version and is re-checked when the pin moves. Timeout, cancel, disconnect mid-call, full queue and shutdown with calls in flight each get a test under TSan and ASan.

## Coding standard: the OpenGDS C rules

Derived from SEI CERT C (2016 edition and the wiki) and MISRA C:2023. We do not claim MISRA compliance; we adopt the rules that catch real bugs in a networked daemon, and every rule says how it is enforced. The rules apply to OpenGDS, the Auditor and the plugin API; vendored code (open62541, OpenSSL) is excluded.

### Language and dialect

| Rule | Enforced by |
| --- | --- |
| C11 (`-std=c11`), no GNU extensions except `__attribute__` behind macros in `src/common/compiler.h` | Compiler flags, `-Wpedantic` |
| No variable-length arrays, no `alloca`, no recursion in code reachable from the network | `-Werror=vla`, clang-tidy `misc-no-recursion`, grep check in CI |
| No `goto` except forward jumps to a single cleanup label at the end of the function | Review; clang-tidy custom check |
| Every `switch` on an enum handles every value and has no `default` (so the compiler finds new values); fall-through must be marked | `-Werror=switch-enum`, `-Werror=implicit-fallthrough` |
| No implicit signed/unsigned or narrowing conversions | `-Wconversion -Wsign-conversion` as errors in our code |
| Banned functions: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `strtok`, `atoi`, `atol`, `atof`, `rand`, `system`, `popen`, `tmpnam`, `mktemp` | `src/common/banned.h` poisons them with `#pragma GCC poison`; CI grep |
| `printf`-style functions only with literal formats | `-Werror=format-security -Wformat=2`, `__attribute__((format))` on our wrappers |

### Memory and ownership

Every pointer in a public or internal signature has exactly one of three meanings, and the name or a comment says which:

| Kind | Meaning | Convention |
| --- | --- | --- |
| Borrowed | Callee reads it during the call only | `const T *`; the default |
| Taken | Callee becomes the owner and frees it | Parameter named `owned_*`, or function named `*_take` |
| Returned | Caller becomes the owner | Out-parameter `T **out` or `T *out` that the callee initialises; caller frees with the matching `*_free` / `*_clear` |

Further rules:

- Constructor/destructor pairs are always `x_new`/`x_free` (heap object) or `x_init`/`x_clear` (caller's storage), matching open62541's own convention. `x_free(NULL)` and `x_clear` on a zeroed object are no-ops. After free, the owner sets its pointer to NULL.
- Every allocation result is checked. Allocation failure returns `GDS_ENOMEM`, which maps to `Bad_OutOfMemory`. Tests inject allocation failures (`tests/unit/test_alloc_fail.c` drives every unit with a failing allocator after N calls).
- All sizes are `size_t`. Every multiplication or addition that produces a size uses `gds_add_size` / `gds_mul_size` from `src/common/safeint.h` (built on `__builtin_*_overflow`, which matches C23 `ckd_add`). A failed check is `GDS_EOVERFLOW`.
- No raw `(pointer, length)` pairs across module boundaries: use `gds_buf` (`{uint8_t *data; size_t len; size_t cap;}`) or open62541's `UA_ByteString`, and the bounds-checked accessors in `src/common/buf.h`.
- `UA_String` is not NUL-terminated. Never pass `.data` to a C string function. Convert with `gds_str_dup` (bounded, rejects embedded NUL) when a C string is needed.
- Per-call arena allocators (`src/common/arena.c`) for request handling, freed once at the end; nothing allocated in an arena may outlive the call.
- Fixed-size arrays only with a bound check at every write; string formatting only with `snprintf`, checking for truncation (`gds_snprintf` returns an error on truncation, the result is never silently cut).
- Flexible array members only as `[]` (never `[1]` or `[0]`), so `-fstrict-flex-arrays=3` and `_FORTIFY_SOURCE=3` see the real size.

### Error handling

- One internal error type, `gds_status` (enum in `src/common/errors.h`), and one function that maps it to `UA_StatusCode`. Every function that can fail returns it and is marked `GDS_MUST_CHECK` (`__attribute__((warn_unused_result))`).
- Structure: check arguments, do the work, single `cleanup:` label that frees in reverse order. No early `return` after the first allocation.
- **Fail closed.** If a check cannot be completed (store unreachable, clock unsynchronised, policy plugin error), the request is refused. Access control never defaults to allow.
- **No partial state.** Multi-step state changes go through a store transaction; the certificate is committed before it is returned (plan rule), and an error rolls everything back.
- Errors sent to peers are standard status codes only. Details (paths, OpenSSL error strings, SQL errors) go to the log, never to the wire. Authentication failures all return the same code and take the same time.
- OpenSSL errors are drained (`ERR_get_error` loop) and logged at the call site, so a stale error never surfaces later.
- `abort()` only for broken invariants that mean memory is already corrupt (`GDS_ASSERT`, kept in release builds). Never for input errors.

### Input validation and limits

Every value from the network is untrusted until checked, even after open62541 has decoded it.

- Method callbacks check every input's type, scalar/array shape and array length before touching `.data`, through one helper: `gds_arg_scalar(&input[i], &UA_TYPES[...], &out)` / `gds_arg_array(...)`. open62541 already checks argument types against the InputArguments property; we check again because a mistake in a nodeset or a library change would otherwise become a memory bug.
- Every method output from a remote server (client side, push engine, Auditor) is checked the same way before use.
- Every input has an upper bound in `src/common/limits.h`, configurable down but not up past a compiled maximum:

| Input | Default limit |
| --- | --- |
| CSR size | 16 KiB |
| Certificate size | 16 KiB; chain at most 8 certificates |
| Trust list file (encoded) | 4 MiB; at most 1,000 certificates and 1,000 CRLs |
| Single CRL | 1 MiB |
| String fields (URIs, names) | 4 KiB; ApplicationUri 1 KiB |
| DiscoveryUrls, ApplicationNames, ServerCapabilities arrays | 32 entries each |
| QueryApplications maxRecordsToReturn | 1,000 per call |
| Open file handles per session (TrustList) | 4 |
| Pending requests per application | 4 |
| Sessions, sessions per client certificate | 500, 8 |
| Message size, chunk count | open62541 limits set explicitly (not left at defaults) |

- All certificates and CSRs are parsed by OpenSSL only, with the size checked first. After parsing, the DER is re-encoded and compared with the input, so two parsers can never disagree about what was signed.
- Text that reaches logs is escaped (control characters, newlines), so a peer cannot forge log lines.

### Cryptography and secrets

- All cryptography goes through OpenSSL 3 EVP APIs. No algorithm, padding, random number generator or constant-time comparison of our own. The plan's rule stands: cryptographic code is never AI-generated without a line-by-line review against OpenSSL's documentation.
- Randomness only from `RAND_bytes` (return value checked; failure refuses the operation). Certificate serials are 128 random bits (positive, non-zero).
- Comparisons of secrets, MACs and password hashes use `CRYPTO_memcmp`.
- Passwords are hashed with Argon2id (OpenSSL `KDF` "ARGON2ID", 3.2+) with parameters stored per hash, so they can be raised later.
- Secrets live in `gds_secret` buffers (`src/common/secmem.c`): `mmap`'d pages with `mlock`, `MADV_DONTDUMP`, guard pages, wiped with `OPENSSL_cleanse` on free. OpenSSL's secure heap (`CRYPTO_secure_malloc_init`) is turned on in the signer for private key material.
- Processes holding secrets set `PR_SET_DUMPABLE` to 0 and `RLIMIT_CORE` to 0.
- Secrets are never logged, never put in error messages, never passed on a command line or in the environment. The CA passphrase arrives through systemd credentials (`LoadCredentialEncrypted=`), a TPM-sealed blob, or a PKCS#11 PIN file readable only by the signer's user.
- Generated application keys (StartNewKeyPairRequest) are created in the signer, encrypted under the caller's password inside the signer, and stored only in that encrypted form until FinishRequest delivers them; then deleted.

### Logging and audit

- Logging wraps `UA_Logger`; one JSON object per line. Log levels never change security behaviour.
- The audit log is separate from the operational log, hash-chained (SHA-256), and written in the same store transaction as the change it records.

## Secure defaults

What a fresh `opengdsd` does with an empty config:

| Area | Default | How to change |
| --- | --- | --- |
| Endpoints | SignAndEncrypt only; ECC policies first, then Aes256_Sha256_RsaPss, Aes128_Sha256_RsaOaep, Basic256Sha256; SecureChannelEnhancements on | Config can remove policies; cannot add None, Basic128Rsa15 or Basic256 |
| None policy | Discovery only (GetEndpoints, FindServers); the library flag `securityPolicyNoneDiscoveryOnly` set and verified at start-up | Not configurable |
| User tokens | X.509 user certificates; UserName only if a password user exists, and never over a None channel; Anonymous never | Config |
| Approval | Manual for new applications; auto-approve only for renewals by the holder of the prior certificate | Policy properties (SecurityAdmin) |
| Admin roles | No role has an identity until `gdsctl init`; `init` refuses one identity for all three admin roles without `--single-admin` | `gdsctl`, Part 18 methods |
| Key sizes | RSA at least 2048 (3072 for new CAs), ECC P-256 or stronger | Config can raise, not lower |
| Validity | 1 year application certificates, ±10% jitter | Policy |
| Clock | Refuses to issue while the system clock is not synchronised | `--allow-unsynchronised-clock` for labs, logged on every issuance |
| Files | State directory 0700, keys 0600, refuses to start if permissions are looser or the owner is wrong | Not configurable |
| Plugins | Built-in only; `dlopen` only from a root-owned directory not writable by others, file checked the same way | Config lists plugins by name |
| Limits | Every limit in the limits table set | Config can lower |
| Telemetry | None | — |

## Build hardening

`cmake/hardening.cmake` defines one interface target, `gds_hardening`, that every OpenGDS and Auditor target links, and passes the same flags to open62541's build through `cmake/open62541.cmake`.

| Flag | Purpose | Compilers |
| --- | --- | --- |
| `-O2 -D_FORTIFY_SOURCE=3` (with `-U_FORTIFY_SOURCE` first) | Bounds checks on libc calls, including dynamic sizes | GCC ≥ 12, Clang ≥ 16 |
| `-fstack-protector-strong` | Stack canaries | both |
| `-fstack-clash-protection` | Stack clash | both |
| `-fcf-protection=full` (x86-64), `-mbranch-protection=standard` (arm64) | CET / BTI+PAC control-flow protection | both |
| `-ftrivial-auto-var-init=zero` | No uninitialised stack reads | GCC ≥ 12, Clang ≥ 16 |
| `-fstrict-flex-arrays=3` | Real bounds for trailing arrays | GCC ≥ 13, Clang ≥ 16 |
| `-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing` | Remove optimisations that turn UB into silent security holes | both |
| `-fPIE -pie` (or `-static-pie`) | ASLR for the executable | both |
| `-Wl,-z,relro -Wl,-z,now` | Full RELRO | both |
| `-Wl,-z,noexecstack` | Non-executable stack | both |
| `-Wl,--as-needed -Wl,--no-copy-dt-needed-entries` | No surprise libraries | both |
| `-Wall -Wextra -Wpedantic -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -Wshadow -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Wvla -Wnull-dereference -Wswitch-enum` and `-Werror` | Warnings as errors in our code | both (some GCC only) |
| `-Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion` | Old C pitfalls are errors | both |

Release builds also use LTO and are reproducible (`-ffile-prefix-map`, `SOURCE_DATE_EPOCH`). GCC 14's `-fhardened` is accepted as an alternative and checked to produce the same binary properties with `checksec` in CI.

## Analysis and testing that enforces the rules

| Tool | When | Gate |
| --- | --- | --- |
| GCC and Clang with the warning set above | Every push | Zero warnings |
| ASan + UBSan (`-fno-sanitize-recover=all`) | Every push: unit, integration, spec suite, demo flow | Zero reports |
| TSan | Every push: integration tests | Zero reports |
| Valgrind memcheck | Nightly: unit tests | Zero errors, zero definite leaks |
| GCC `-fanalyzer` | Every push | Zero new findings |
| clang-tidy: `bugprone-*`, `cert-*`, `clang-analyzer-*`, `misc-*`, `readability-function-cognitive-complexity` (≤ 25) | Every push | Zero findings |
| cppcheck with the MISRA addon (advisory) | Every push | Zero errors; MISRA findings reviewed weekly |
| CodeQL `security-extended` | Every push to main and nightly | Zero high findings |
| libFuzzer + ASan/UBSan | Every push: 60 s per target on changed code; nightly: 1 h per target; OSS-Fuzz after 1.0 | Any crash blocks the release |
| Coverage | Every push | 85% lines in `src/` (plan), 100% of `src/signer/` |
| Allocation-failure injection | Every push | No leak, no crash at any failure point |
| `checksec` on built binaries | Every push | PIE, full RELRO, canary, NX, FORTIFY present |
| OpenSSF Scorecard | Weekly | Score tracked, no regression |

**Fuzz targets** (`tests/fuzz/`, seeds in `tests/fixtures/`):

- `fuzz_csr.c`: CSR checks in the signer, from raw DER.
- `fuzz_cert_chain.c`: UpdateCertificate chain validation (client side and Auditor).
- `fuzz_trustlist.c`: TrustListDataType decode, limits and install, on both sides.
- `fuzz_app_record.c`: ApplicationRecordDataType validation in RegisterApplication / UpdateApplication.
- `fuzz_query.c`: QueryApplications filters and paging.
- `fuzz_methods.c`: every Part 12 method callback called in-process (`UA_Server_call`) with fuzzed variant arguments, sessions and roles; asserts that no call from a non-admin session changes the store.
- `fuzz_signer_ipc.c`: the signer's request decoder.
- `fuzz_config.c`: the daemon config parser.
- `fuzz_auditor_responses.c`: the Auditor's handling of hostile method results.

## Run-time containment

**Inside the process** (`src/common/sandbox.c`), after configuration is read and sockets are bound:

1. Drop privileges if started as root (`setgroups`, `setgid`, `setuid`, checked), then `PR_SET_NO_NEW_PRIVS`.
2. Landlock: read-only access to config and PKI trust directories, read-write to the state directory, nothing else. Skipped with a warning on kernels without Landlock; the systemd unit covers those.
3. seccomp-BPF allowlist (libseccomp): the system calls the daemon actually uses (network, files, futex, time, mmap/mprotect without `PROT_EXEC` on writable pages). `execve`, `ptrace`, `mount`, `bpf` and `keyctl` are killed. The signer's filter is narrower: no `socket`/`connect`, only its inherited socket.

**Around the process** (`packaging/systemd/`): `DynamicUser=` or a fixed system user, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes` (signer: device allow-list for TPM/HSM only), `ProtectKernelTunables/Modules/Logs=yes`, `ProtectControlGroups=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (signer: `AF_UNIX`), `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `SystemCallArchitectures=native`, `CapabilityBoundingSet=` empty (`CAP_NET_BIND_SERVICE` only if a port below 1024 is configured), `UMask=0077`, `LoadCredentialEncrypted=` for secrets, `WatchdogSec=`. Target: `systemd-analyze security` exposure score under 2.0 for both units.

**Containers**: distroless, non-root, read-only root filesystem, the same seccomp profile exported as JSON; signer and daemon as two containers sharing one socket volume.

**No shell-outs.** OpenGDS never executes another program. The Auditor's `--trigger-cmd` and `--restart-cmd` hooks are the only exception: they run with `posix_spawn` from an argv array (never through `/bin/sh` unless the operator writes it so), with a timeout, a cleared environment plus an allow-list, and their output captured as evidence.

## Plugin API rules

The plugin API (`include/opengds/`) is the seam UASM builds on, so its shape decides how safe UASM can be.

- Every plugin struct starts with `uint32_t abi_major, abi_minor; size_t struct_size;`. The core refuses another major and reads only the fields that `struct_size` covers, so minor versions can add fields at the end without breaking old plugins.
- Ownership is in the signature (borrowed, taken, returned as above), documented on every function, and checked by `tests/integration/test_plugin_abi.c` under ASan.
- Plugins get `const` views of records and copy what they keep. No plugin receives a pointer into open62541 request memory.
- Every plugin call has a timeout budget; the core calls plugins from worker threads only, never from the network thread, and never while holding a lock.
- Plugin errors fail closed: a policy plugin error refuses the request; an event sink error is logged and counted but never blocks an issuance (audit goes to the store first).
- The CA slot runs in the signer, so CA plugins (UASM ceremonies, HSM profiles) get the signer's protections; store, policy, events, push and cluster plugins run in `opengdsd`.
- The cluster slot (`opengds_set_role`) is the only way to change the node role; on a standby the core refuses state-changing methods with `Bad_InvalidState` before any plugin sees them.
- Plugin API headers compile cleanly under `-std=c11 -Wpedantic -Werror` and C++17, and contain no open62541 types except stable ones (`UA_StatusCode`, `UA_NodeId`, `UA_ByteString`, and for method plugins `UA_Variant` and `UA_Argument`, which carry method arguments in OPC UA's own encoding), so a library upgrade does not break the ABI.

## The Auditor under these rules

The Auditor is a test tool, but it runs against live plant devices and reads their answers, so it gets the same rules with three additions:

- **Target answers are hostile input.** Every result from a target is validated like network input (type, shape, limits) before a test looks at it, and `fuzz_auditor_responses.c` covers that path. A malformed answer is a Fail with evidence, never a crash.
- **Test PKI is marked.** Test CA certificates carry "OpenGDS Auditor TEST" in the subject and a validity of at most 30 days, and test keys are never written outside the run's results folder. The fake GDS in the client profile breaks rules on purpose but listens only on localhost unless `--listen-any` is given.
- **Writes are guarded.** `--allow-changes`, snapshot and restore are as in the Auditor plan; restore runs from a signal-safe path (the signal handler only sets a flag; the main loop restores).
- **Self-test targets are not products.** `selftest/push_test_server` and `selftest/pull_test_client` exist to be tested against, including with `--break` mutants. They print a banner saying so and refuse to bind a non-loopback address with a mutant active.

## Files

New or changed files, in the plan's file-by-file style.

| File | Responsibility |
| --- | --- |
| `cmake/hardening.cmake` | `gds_hardening` interface target, flags above, compiler feature checks |
| `cmake/sanitizers.cmake` | `OPENGDS_SANITIZE=address;undefined`, `thread`, `memory` presets |
| `cmake/open62541.cmake` | Pinned v1.5.10 build with only the needed features and the hardening flags |
| `cmake/analysis.cmake` | `clang-tidy`, `cppcheck`, `-fanalyzer` targets |
| `.clang-tidy`, `.clang-format` | Check set and format |
| `src/common/compiler.h` | `GDS_MUST_CHECK`, `GDS_FORMAT`, `GDS_NONNULL`, `GDS_ASSERT` |
| `src/common/banned.h` | Poisoned functions, included last by every source file |
| `src/common/safeint.h` | Checked size arithmetic |
| `src/common/buf.h/.c` | `gds_buf`, bounded reads and writes, file I/O with size limits and atomic replace (`write` to temp, `fsync`, `rename`) |
| `src/common/limits.h` | Compiled maxima and defaults for every input |
| `src/common/args.h/.c` | Method argument and result checks (`gds_arg_scalar`, `gds_arg_array`) |
| `src/common/arena.c/.h` | Per-call arenas |
| `src/common/secmem.c/.h` | `gds_secret` (from the plan, extended) |
| `src/common/sandbox.c/.h` | Privilege drop, Landlock, seccomp |
| `src/ca/ca_ipc.c` | CA slot client that forwards to the signer |
| `src/signer/main.c` | Signer entry point, sandbox, request loop |
| `src/signer/proto.c/.h` | Fixed, versioned, length-prefixed request and reply encoding; fuzzed |
| `src/signer/checks.c` | Re-reads record and approval from the store, rate limits |
| `src/signer/journal.c` | Signer's own hash-chained issuance log |
| `src/gdsctl/verify_audit.c`, `main.c` | `gdsctl verify-audit`: one store against the journals of every node's signer |
| `src/gdsctl/backup.c` | `gdsctl backup` / `restore`: an online store snapshot and the CA directory (key, certificate, CRL, issuance journal) in one AES-256-GCM archive keyed by scrypt of a backup passphrase. Restore authenticates the archive, then puts it in place only if `verify-audit` finds nothing but "signed, not committed" (other nodes' journals can be given) |
| `packaging/systemd/opengds-signer@.service`, `opengds-signer.socket` | Signer unit (one instance per opengdsd connection, `Accept=yes`) and the socket between the two |
| `docs/memory-safety.md` | Published memory-safety roadmap (F1) |
| `docs/locking.md` | Lock order and thread ownership |
| `tests/unit/test_alloc_fail.c` | Allocation failure injection |
| `tests/fuzz/fuzz_methods.c`, `fuzz_signer_ipc.c`, `fuzz_cert_chain.c`, `fuzz_config.c`, `fuzz_auditor_responses.c` | New fuzz targets |
| `.github/workflows/ci.yml` | Matrix: GCC/Clang × release/ASan+UBSan/TSan, analysis jobs, checksec |
| `.github/workflows/codeql.yml`, `scorecard.yml` | CodeQL and OpenSSF Scorecard |

## Supply chain

- Dependencies pinned by version **and** hash: open62541 by tag and commit SHA, OpenSSL by tarball SHA-256, SQLite amalgamation by SHA-256. The build fails on a mismatch.
- GitHub Actions pinned by commit SHA; Dependabot proposes updates; workflows run with `permissions: contents: read` unless they need more.
- Releases: reproducible builds checked by a second builder, signed tags, artefacts signed with Sigstore (cosign), SLSA build provenance, SPDX SBOM.
- Branch protection on main: review required, CI green, signed commits, DCO sign-off.

## Changes to the plans

| Plan | Change | Why |
| --- | --- | --- |
| OpenGDS: Architecture ("one daemon process holds everything") | CA key moves to a separate `opengds-signer` process; `ca_ipc.c` fills the CA slot in `opengdsd`; in-process CA kept for tests and embedding | A memory bug in the network process must not reach the CA key |
| OpenGDS: Dependencies | OpenSSL minimum 3.5 instead of "3.x"; libseccomp added (LGPL 2.1, Linux only, optional at build time) | F3; seccomp |
| OpenGDS: `cmake/open62541.cmake` | Reconsider `UA_ENABLE_HISTORIZING=ON` (not needed for Part 12; audit history lives in the store); hardening flags passed to the library; PubSub and MQTT off (JSON and XML are required in v1.5.10: events, and the nodeset Value attributes) | F2, smaller attack surface |
| OpenGDS: pinning | Exact pin stays; security patch releases of 1.5.x adopted within 14 days as one reviewed commit | F2 |
| OpenGDS: `src/common/` | Adds `compiler.h`, `banned.h`, `safeint.h`, `buf.*`, `limits.h`, `args.*`, `arena.*`, `sandbox.*` | Rules need homes |
| OpenGDS: CI | Adds GCC `-fanalyzer`, allocation-failure injection, checksec, Scorecard; analysis gates at zero findings | F7 |
| OpenGDS: timeline | Signer adds about 1.5 coding days in T1 (thin version: `SIGN_CSR` only) and 1 day in W2; sandboxing about 1 day in MVP. Calendar-bound work unchanged | AI-assisted estimate; review time included in the calendar, not compressed |
| OpenGDS: Risks, "A&C experimental" | Downgrade to low: DialogCondition approvals with Respond2 work in v1.5.10 with three small workarounds, kept in `gds_approvals.c`, the only file that touches A&C; the hand-rolled event fallback is dropped | docs/spikes/01 |
| OpenGDS: `gds_certmgr.c`, `gds_config.c`, `src/common/threadpool.c` | Signing as a background job, not an async call; server-thread handoff for async results; queue and timeout bounds above | docs/spikes/02 |
| OpenGDS: `tests/spec/test_spec_events.c` | Refresh after restart shows pending dialogs; Respond and Respond2 both work; second answer gives `Bad_DialogNotActive`; wrong role gives `Bad_UserAccessDenied`; more pending dialogs than the queue cap | docs/spikes/01 |
| Auditor: core | Response validation and `fuzz_auditor_responses.c`; hooks via `posix_spawn` | Hostile targets |
| UASM | CA ceremony plugin and HSM profiles load into the signer; per-node signer in the cluster | Same protection for the commercial CA path |

## Decisions this document asks for

These change a plan, so they are Elias's call. The document assumes the first option of each until decided.

1. Separate signer process for the CA key (recommended) or keep the single process of the original plan.
2. OpenSSL 3.5 as the minimum (recommended, since 3.0 is out of support) or keep 3.0 compatibility.
3. Turn `UA_ENABLE_HISTORIZING` off until a feature needs it (recommended).

## Appendix A: demo code review

Findings from reviewing the demo (2 Nov 2026) against these rules. Each is fixed when the file moves into `tools/auditor/`.

| File | Finding | Fix |
| --- | --- | --- |
| `common/x509util.c` | `malloc` results not checked in `buf_read_file`, `x509_to_der`, `key_to_der`, `x509_make_csr`, `testca_crl_der`; `ftell` result used without a size limit | Checked allocations; size limit per file type; `gds_buf` |
| `common/x509util.c` | `buf_write_file` writes in place (a crash leaves a half-written key or certificate); key files written with the default umask before `chmod` | Write to a temp file opened with mode 0600, `fsync`, `rename` |
| `common/x509util.c` | `RAND_bytes` result ignored when making serials; `X509_*` return values often ignored | Checked; failure aborts issuance |
| `common/x509util.c` | `x509_thumbprint` ignores `EVP_Digest` failure; uses `sprintf` | Checked; hex encoder without `sprintf` |
| `common/x509util.c` | `testca_sign_csr` keeps the CSR subject (fine for a fixture, documented) | Kept in the fixture with a comment; the real CA never does this |
| `common/uaclient_util.c` | `uac_read_trustlist` grows a buffer with unchecked `realloc` and no upper bound: a hostile server can exhaust memory; `outV[0].data` dereferenced without checking type or size | Limit from `limits.h`; checked growth; `gds_arg_scalar` on every result |
| `common/uaclient_util.c` | `calloc` results not checked; global step counter | Checked; counter in a context struct |
| `tools/pull_test_client.c` | Method results (`out[0].data`, `out[1].data`, `out[2]`) used without type or length checks; `atoi` | Checked results; `strtol` with range check |
| `tools/pull_test_client.c` | Private key file written with default permissions | 0600 via the atomic writer |
| `tools/pull_test_client.c` | Password passed on the command line (visible in `ps`) | `--password-file` added; `--password` kept for scripts with a warning |
| `tools/push_test_server.c` | Session flag list is a global linked list without a lock (fine with the single-threaded server; documented) | Kept; assertion that the server runs single-threaded |
| `tools/push_test_server.c` | Admin passwords kept in fixed 64-byte arrays, silently truncated | Length checked; refused if too long |
| `tools/push_test_server.c` | Anonymous sessions allowed (non-admin) | Kept on purpose for refusal tests, documented, and `--no-anonymous` added |
| `fixtures/mock_gds.c` | Inputs dereferenced without type checks (`input[0].data`, `input[3].data`); `rand()` for file handles | `gds_arg_*` checks; `RAND_bytes` |
| `fixtures/mock_gds.c` | Accepts any client certificate on the channel (by design for Annex G.1 step 1) | Kept, documented; loopback by default |
| `fixtures/push_driver.c` | Trust on first use of the server certificate (by design for test setups) | Kept behind an explicit `--tofu` flag, off by default |
| `run_demo.sh` | Fixed ports, `sleep`-based waits | Ports from the environment; wait on log line with a timeout (already present), used as a CTest test |

## Sources

- CISA and FBI, [Product Security Bad Practices](https://www.cisa.gov/resources-tools/resources/product-security-bad-practices) (v2, Jan 2025), memory-safety roadmap guidance; summary in [the IC3 advisory PDF](https://www.ic3.gov/CSA/2024/241016-2.pdf)
- CISA, NSA et al., [The Case for Memory Safe Roadmaps](https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps) (Dec 2023)
- OpenSSF, [Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++)
- OpenSSF, [Scorecard](https://github.com/ossf/scorecard); [SLSA](https://slsa.dev/)
- SEI CERT, [C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)
- MISRA, [MISRA C:2023](https://misra.org.uk/product/misra-c2023/)
- MITRE, [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- open62541 [SECURITY.md and advisories](https://github.com/open62541/open62541/security/advisories); 2026 CVE summary at [Aviatrix threat research](https://aviatrix.ai/threat-research-center/o6-automation-open62541-vulnerabilities-2026/); Fedora update to 1.5.6 fixing FindServers and endpoint URL DoS issues, [FEDORA-2026-23b21104ef](https://linuxsecurity.com/advisories/fedora/fedora-44-open62541-2026-23b21104ef); CISA ICS advisory ICSA-26-211-08
- OpenSSL, [roadmap and LTS dates](https://openssl-library.org/roadmap); [OpenSSL 3.0 end of life, 7 Sep 2026](https://endoflife.ai/article-openssl-eol); [Argon2 KDF](https://docs.openssl.org/3.5/man7/EVP_KDF-ARGON2/); [secure heap](https://docs.openssl.org/3.5/man3/CRYPTO_secure_malloc/)
- Diemunsch, Hirschi, Kremer, [A Comprehensive Formal Security Analysis of OPC UA](https://eprint.iacr.org/2025/148), USENIX Security 2025
- Linux kernel, [Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html); [seccomp filter](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- systemd, [systemd.exec(5) sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Sandboxing); [systemd-analyze security](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html)
- LLVM, [libFuzzer](https://llvm.org/docs/LibFuzzer.html); Google, [OSS-Fuzz](https://google.github.io/oss-fuzz/)
- GCC, [`-fanalyzer`](https://gcc.gnu.org/onlinedocs/gcc/Static-Analyzer-Options.html) and [`-fhardened`](https://gcc.gnu.org/gcc-14/changes.html)
- European Union, [Cyber Resilience Act, Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- OpenGDS plan (01), UASM plan (02) and Auditor plan (03), 3–5 Nov 2026
