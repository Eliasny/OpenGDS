# OpenGDS performance

The OpenGDS plan sets performance targets ("Performance design and targets")
for a 4-core x86-64 server. `tests/perf/` measures each one against a real
`opengdsd` with `opengds-signer`, over standard OPC UA on localhost.

## Running

```sh
cmake --build build --target perf          # all tools, then run_perf.sh
# or by hand, with smaller sizes:
APPS=5000 AGENTS=50 DEVICES=8 PUSH_PARALLEL=8 PUSH_JOBS=32 \
    sh tests/perf/run_perf.sh build /tmp/perf-run
```

The results land in `<work-dir>/results.txt` as `RESULT <name> <value> <unit>`
lines, with `ERRORS <step> <StatusCode> <count>` lines for failed calls and
`opengdsd`'s own error lines at the end. A full run takes about 4 minutes.

| Variable | Default | What |
|---|---|---|
| `APPS` | 50000 | applications `bench_register` registers |
| `REG_THREADS` | 16 | parallel sessions registering them |
| `AGENTS` | 500 | concurrent pull agents in `load_pull` |
| `DEVICES` | 64 | `push_test_server` instances for `load_push` |
| `PUSH_PARALLEL` | 64 | parallel push sessions |
| `PUSH_JOBS` | 256 | pushes in total |
| `SIGN_SECONDS` | 5 | CPU seconds of each `bench_sign` measure, in 0.25 s rounds |

64 devices need more inotify instances than the Linux default of 128 per user
(open62541's file certificate store takes them):
`sysctl -w fs.inotify.max_user_instances=1024`. The script checks first.

The perf tools are built with the tests but are not registered with ctest:
they take minutes and their numbers depend on the host. There is no CI job;
the plan's "CI fails on a regression over 10%" needs a workflow change and a
stable runner, and is left for later.

## The tools

| Tool | Measures |
|---|---|
| `bench_sign` | `gds_ca_sign_csr` through the CA slot with the built-in OpenSSL backend (the code `opengds-signer` runs), against the bare `EVP_PKEY_sign` with a key of the CA's type and size, which is what `openssl speed` times. Single thread, thread CPU time; the bare and the CA measure alternate in 0.25 s rounds and the ratio is the median of the rounds' ratios. RSA and P-256 issuers. |
| `bench_register` | RegisterApplication (OPC 10000-12 §6.5.5) rate from T sessions until the store holds `APPS` records, then FindApplications latency at that size. |
| `load_pull` | N pull agents, each with its own SignAndEncrypt session: first all sessions are opened and held together (concurrent sessions), then each runs RegisterApplication, StartSigningRequest/FinishRequest (polled every 20 ms) and GetTrustList with every session still open. |
| `load_push` | P workers, each with a GDS session, push to D `push_test_server` devices the way `gdsadm push now` does (§7.7.2, Annex G.3): trust list, CreateSigningRequest, signing on the GDS, UpdateCertificate, ApplyChanges. Reports pushes per second and what that covers in 24 h. |
| `run_perf.sh` | Starts `opengdsd` + `opengds-signer` (approval `auto`), runs the tools in order, reads resident memory from `/proc`, and times a cold start of `opengdsd` on the full store. |

## Results

Local run on 2026-11-09, `main` at d711b77 plus this change: 4 vCPU Intel
Xeon @ 2.10 GHz, 16 GiB, Linux 6.18, clang Release build, OpenSSL 3.5.9,
open62541 v1.5.10 with OpenGDS's patches. The load generators run on the
same 4 CPUs as the GDS, so throughput figures are lower bounds. Ranges are
over three full runs.

No CI runner result yet: GitHub Actions is not usable for this project at
the moment (Elias, 2026-11-09).

| Target | Measured | Verdict |
|---|---|---|
| 50,000 registered applications | 50,000 registered; store 16 MiB; FindApplications p50 0.07 ms, p99 0.3 ms | met; the 2 to 6 failed registrations per run are fixed (finding 3) |
| RegisterApplication 1,000 per second | 1,780 to 2,140 per second from 16 sessions; p50 6.7 ms, p99 19 ms | met |
| 500 concurrent sessions | 500 open at once, then 500 pull workflows with every session held (before finding 1 was fixed: 100, the other 400 refused) | met (finding 1) |
| RSA-2048 issuance within 10% of `openssl speed` | CA slot 820 to 870 certificates/s against 910 to 960 bare RSA-3072 signatures/s: **88 to 91%** in CPU time, 97.7% in instructions (before finding 2: 81 to 87%) | borderline (finding 2) |
| Push coverage 10,000 servers per 24 h with 64 parallel sessions | 256 pushes to 64 devices in 10 s: 25.5 per second, about 2.2 million per 24 h | met |
| Daemon memory at 50,000 apps under 150 MB | `opengdsd` 26 MiB (31 MiB after the pull load), `opengds-signer` 8 MiB | met |
| Cold start with 50,000 records under 2 s | 0.35 to 0.40 s to listening | met |
| Renewal storms spread over at least 20% of the lifetime | not measured: needs the push scheduler (W3) | open |

Other numbers from the same run:

- P-256 issuance: 5,350 certificates/s in the CA slot against 41,000 bare
  ECDSA signatures/s (13%). ECDSA signing is so cheap that parsing and
  checking the CSR and building the certificate dominate; the plan's 10%
  bound is stated for RSA only.
- Pull workflow with 100 sessions working at once: register p50 59 ms, sign
  (StartSigningRequest to certificate, through the signer) p50 201 ms,
  GetTrustList p50 116 ms, whole workflow p95 395 ms; 100 certificates in
  0.5 s.
- Opening a session (SecureChannel with RSA, UserName with PBKDF2): p50 1.5 s
  while 500 clients connect at once on the same 4 CPUs.
- Push: a job takes about 2 s, almost all of it on the device
  (`push_test_server` applies changes after a short delay); the GDS's part,
  StartSigningRequest to certificate, is p50 25 ms, p99 122 ms.

## Findings

1. **Sessions are capped at 100.** `opengdsd` leaves open62541's
   `maxSessions` and `maxSecureChannels` at their default of 100. The 101st
   client gets its SecureChannel closed. The per-session tables in
   `gds_access.c` and `gds_audit.c` already hold 1,024. Raising the two
   limits (and choosing what happens under load, plan §6.3 "idle sessions are
   closed first") is a product change for the MVP thread. **Fixed:**
   `max_sessions` in `opengds.conf` (default 500, at most 1,000) sets
   `maxSessions`, and `maxSecureChannels` gets a tenth more. When a table is
   full, open62541 closes the oldest SecureChannel without a Session, or the
   oldest Session not yet activated, so a client that has not authenticated
   cannot hold a slot (`docs/opengdsd.md`). Rerun 2026-11-09 on the same host
   (`AGENTS=500`): 500 sessions open together, 500 certificates issued
   (212/s), whole workflow p95 2.1 s. Opening 500 sessions at once takes
   16.9 s on 4 CPUs (connect p50 6.3 s, p99 16.5 s): the RSA SecureChannel
   and the PBKDF2 password check of every client compete for the CPUs.
2. **CA issuance is 13 to 19% under the bare signature.** The CA's own
   private-key operation is RSA-3072 (`caKeyBits` default), so the bare
   baseline is `openssl speed rsa3072`, about 915 signatures/s on this host;
   issuing reaches 760 to 800. The rest is the CSR parse and its
   proof-of-possession check, building the certificate from the record, and
   DER encoding. With an RSA-2048 CA key every number would roughly triple,
   but the ratio is what the target names. **Rework, 2026-11-09:**
   - Profile (callgrind, RSA only): issuing one certificate is 32.5 million
     instructions against 31.8 million for the bare signature (97.7%);
     `X509_sign` itself costs what the bare signature costs. Of the rest,
     encoding the CSR's key again for the certificate
     (`X509_set_pubkey`, through the provider encoders) was the largest
     part, 23 µs for RSA-2048 and 31 µs for P-256.
   - The certificate now takes the CSR's subjectPublicKeyInfo as it is
     when it is already in the one form `X509_set_pubkey` would write
     (rsaEncryption with NULL parameters and a DER RSAPublicKey; P-256 or
     P-384 named curve with an uncompressed point), and encodes the key
     again otherwise (`cax_set_pubkey_from_req`, `unit_ca_pubkey`).
   - `bench_sign` measured the bare signature and then the CA for 5 s each
     in wall-clock time; on this shared host the speed drifts by 10 to 20%
     within a minute, which landed on one side. It now uses the thread's
     CPU time and alternates the two in 0.25 s rounds.
   - Rerun, three runs of 10 s: RSA 88.2, 91.2 and 89.6% (P-256 issuance
     5,700 certificates/s, up from 4,400 to 4,900). The remaining gap in
     time is larger than in instructions; most likely the CSR decode and
     certificate build between two signatures push the modular
     exponentiation's code and tables out of the CPU caches (not measured:
     no hardware counters in this VM). On a host with steadier timing (a CI runner or
     bare metal) the number should be rechecked.
3. **A few registrations fail with Bad_InternalError under load.** 2 to 6 of
   50,000 per run; `opengdsd` logs
   `store: insert application: unable to open database file (14)`. SQLite
   needs a temporary file now and then (for example a statement journal), by default in
   `/var/tmp` or `/tmp`, which the Landlock sandbox does not allow. Run with
   `SQLITE_TMPDIR` set to the data directory, the same 50,000 registrations
   had no failures. **Fixed:** the store now opens with
   `PRAGMA temp_store=MEMORY`, so SQLite never asks for a temporary file.
   Rerun 2026-11-09 on the same host (16 sessions, 50,000 applications):
   main 49,995 registered and 5 Bad_InternalError, with the fix 50,000 of
   50,000 and no `unable to open database` in the log.

## Limits of these numbers

- The load generators share the CPUs with the GDS and the signer.
- The push devices are `push_test_server` instances on one host; they all
  have the same ApplicationUri, so they share one GDS record (a duplicate
  ApplicationUri is refused). Every device still has its own key, trust list,
  certificate and session, and the GDS signs for each push.
- Pull agents authenticate as an administrator (UserName) rather than with
  their own application certificate (ApplicationSelfAdmin); the GDS work per
  call is the same.
