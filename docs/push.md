# Pushing certificates and trust lists to a device

OpenGDS manages devices that cannot pull their own certificates with the push model of OPC 10000-12 v1.05.07 §7.7. An administrator can start a push with `gdsadm push now`, and `opengdsd` can push on its own schedule (see Scheduled pushes below).

`gdsadm` is an Administration Component, as Part 12 calls it. It uses only standard OPC UA methods on the GDS and on the device, so any vendor's admin tool could do the same, and `gdsadm` works with any GDS and any push-capable Server.

## What `gdsadm push now` does

1. Connects to the GDS with SignAndEncrypt, its own certificate and a user that has CertificateAuthorityAdmin. The GDS is trusted only through `--trust`.
2. Finds the device's record with FindApplications (§6.5.4), and its trust list with GetTrustList (§7.9.8).
3. Connects to the device with the strongest SecurityPolicy both sides support, refusing None, Basic128Rsa15 and Basic256. The device must map `gdsadm`'s certificate to SecurityAdmin (Annex G.3). The device is trusted through the GDS CA. For the first push to a device that still has its self-signed certificate, `--server-cert` pins that certificate.
4. Writes the trust list first (Open, Write, CloseAndUpdate, §7.7.3), so the CA and CRLs arrive before the certificate that depends on them.
5. Calls CreateSigningRequest on the device. The device keeps its key. The CSR goes to the GDS with StartSigningRequest and FinishRequest (§7.9.4, §7.9.6). The GDS builds the certificate from the registered record (decision G5). Then UpdateCertificate is called with the issuer chain.
6. Calls ApplyChanges if any step asked for it (§7.7.2). If a step fails after the device accepted an earlier one, it calls CancelChanges (§7.10.2).
7. Checks that the device's endpoints now present the issued certificate.

## Example

```sh
CONN="--gds opc.tcp://gds.example:4840 --cert adm.der --key adm.key.der \
      --trust /var/lib/opengds-ca/ca.der --crl /var/lib/opengds-ca/ca.crl \
      --user admin --password-file /etc/opengds/admin.pw"

gdsadm apps register --uri urn:example:press7 --name "Press 7" --type Server \
    --discovery-url opc.tcp://press7.example:4840 $CONN
gdsadm push now urn:example:press7 --server-cert press7-selfsigned.der $CONN   # first push
gdsadm push now urn:example:press7 $CONN                                       # renewals
```

## Scheduled pushes

With `push = true` in `opengds.conf`, `opengdsd` keeps its push targets up to date by itself (`src/push/push_engine.c`). It is off by default.

### Push targets

A push target is a registered Server (or ClientAndServer) with an endpoint. Push targets live in the store, and an administrator manages them on the GDS host with `gdsctl`. There is no OPC UA method for it, so the GDS's OPC UA interface stays as Part 12 defines it.

```sh
gdsctl push-targets add    --store /var/lib/opengds/gds.db --uri urn:example:press7
gdsctl push-targets add    --store /var/lib/opengds/gds.db --uri urn:example:press8 \
                           --endpoint opc.tcp://press8.example:4840 --disabled
gdsctl push-targets list   --store /var/lib/opengds/gds.db
gdsctl push-targets remove --store /var/lib/opengds/gds.db --uri urn:example:press8
```

Without `--endpoint`, the first `opc.tcp://` DiscoveryUrl of the record is used. A target goes away with its record (UnregisterApplication). `opengdsd` picks up changes at its next look, so it can keep running. These offline writes raise no OPC UA audit event.

### What the engine does

Every `push_interval` seconds the engine looks for due jobs, and runs at most `push_concurrency` at once. A job does the same steps as `gdsadm push now`, with the GDS's own application certificate as the identity: the device must map that certificate to SecurityAdmin (Annex G.3). A job first looks at the device: the certificate its endpoint presents and, when needed, its trust list. Only what differs is pushed. The engine keeps no state on disk, so a job that runs twice changes nothing the second time.

A target is due:

- when the engine first sees it (on start, when it is added, or when this node becomes primary);
- for a new certificate when a third of the current certificate's lifetime is left, or when the device presents a certificate that this GDS did not issue;
- for its trust list when the DefaultApplicationGroup trust list changes, for example after a revocation (new CRL) or after a certificate is trusted;
- for GetRejectedList (§7.10.12) every `push_rejected_interval` seconds.

Every job waits a random delay of up to `push_jitter` seconds, so that many targets do not all connect at the same moment. After a failure the target waits `push_backoff_min` seconds, then twice as long after each further failure, up to `push_backoff_max`, plus the jitter.

With redundancy, only the primary pushes. A standby does nothing, and a node that becomes primary looks at every target again.

The first push to a device that still has its self-signed certificate needs that certificate pinned, so it stays a manual step: `gdsadm push now --server-cert`. After that the engine renews the certificate. It pushes only RSA application certificates (the DefaultApplicationGroup RsaSha256 type) for now.

### Rejected clients

GetRejectedList returns the certificates a device refused. For each client certificate that the GDS does not already trust, the engine opens a DialogCondition (OPC 10000-9 §5.6) named `Rejected_<hash>` on the object `Push` (namespace `urn:opengds:push`) with the options "Register and trust" and "Ignore". A user with DiscoveryAdmin answers it with Respond or Respond2. "Register and trust" registers the application as a Client from the certificate's application URI and adds the certificate to the DefaultApplicationGroup trusted list, which the engine then pushes to every target. At most 64 dialogs are open at a time.

### Configuration

| Key | Default | Range | What |
| --- | --- | --- | --- |
| `push` | `false` | | Run the engine |
| `push_interval` | 60 | 1..86400 s | How often to look for due jobs |
| `push_concurrency` | 4 | 1..64 | Jobs at once |
| `push_jitter` | 300 | 0..86400 s | Random delay of every job |
| `push_backoff_min` | 60 | 1..86400 s | First retry after a failure |
| `push_backoff_max` | 21600 | 1..2592000 s | Longest retry delay, at least `push_backoff_min` |
| `push_rejected_interval` | 3600 | 0..2592000 s | GetRejectedList period, 0 = never |

With `push = true` the sandbox allows `opengdsd` outgoing TCP connections.

### Replacing the schedule

A plugin can replace the choice of which due jobs run (`gds_server_set_push_scheduler` in `src/server/gds_plugin.h`, plugin ABI 1.2), for example to push in waves or only in maintenance windows. The engine still decides what is due, does the work, and reports each result back through `job_done`.

## Setting up a new device (Annex G.2)

A new device that supports PushManagement starts in the application setup
state: its ServerStatus.State is NoConfiguration and
ServerConfiguration.InApplicationSetup is TRUE (OPC 10000-12 Annex G.2).
`gdsadm push setup` takes it out of that state:

```sh
gdsadm push setup --server-url opc.tcp://press7.example:4840 \
    --server-uri urn:example:press7 --server-cert press7-selfsigned.der \
    --setup-user setup --setup-password-file press7-setup.pw $CONN
```

1. Connects with the device's setup credentials (§7.5). The device is
   trusted only through `--server-cert`, the certificate the installer
   registered for it (Annex G.2: the CertificateManager checks that a device
   is one of the pre-authorized ones). A device that already has a
   certificate from the GDS CA is also accepted, and then refused in step 2.
2. Reads ServerStatus.State and InApplicationSetup, and stops unless the
   device is in the setup state.
3. Registers the device in the GDS from the ApplicationDescription it gives
   (RegisterApplication). If the ApplicationUri is registered already, that
   record is used. Registration comes first because StartSigningRequest
   names the ApplicationId (§7.9.3).
4. Pushes the trust list and a certificate as `push now` does, then
   ApplyChanges. If a step fails, CancelChanges discards everything and the
   device stays in setup.
5. Connects again, now trusting the device through the GDS CA, and adds
   `gdsadm`'s ApplicationUri to the device's SecurityAdmin Role (OPC
   10000-18 AddIdentity with an Application rule). An Anonymous rule in that
   Role is removed (Annex G.2: "Add Client ApplicationUri to SecurityAdmin
   Role, remove Anonymous from SecurityAdmin Role").
6. Connects a third time with `gdsadm`'s certificate alone (Annex G.3) and
   checks that the device left the setup state.

After that, `gdsadm push now` needs no device credentials. Without
`--setup-user`, the device must give SecurityAdmin to `gdsadm`'s
certificate while it is in setup. The library behind it is
`src/push/push_setup.h`; the scheduled pushes above do not set up devices.

## Devices behind a firewall (Reverse Connect)

A device that may not accept incoming connections can open them itself
(OPC 10000-6 §7.1.3, Reverse Connect). Configure the device to connect to
the host and port where `gdsadm` listens, and use `--reverse-port` instead
of `--server-url`:

```sh
gdsadm push setup --reverse-port 4843 --server-uri urn:example:press7 \
    --server-cert press7-selfsigned.der --setup-user setup \
    --setup-password-file press7-setup.pw $CONN
gdsadm push now urn:example:press7 --reverse-port 4843 $CONN
```

The session waits up to 60 s for the device's ReverseHello. It uses two
connections from the device: the first for GetEndpoints, the second for the
SignAndEncrypt session (the device opens a new one after the first closes).
The endpoint is the one with the highest SecurityLevel among the policies
`gdsadm` accepts, and None, Basic128Rsa15 and Basic256 are refused as for a
direct connection. The device's certificate and ApplicationUri are checked
the same way. A listening port takes any caller, so `--server-uri` (or the
record's ApplicationUri for `push now`) is required.

## Applications that pull (Annex G.1)

An application that manages its own certificate pulls it from the GDS
(§7.6). `src/client/gdsc_pull_agent.h` is a pull agent a vendor can embed:
one call registers the application if needed, checks GetCertificateStatus,
makes a new key pair and CSR when an update is due, finishes the request
(or keeps a pending RequestId for the next run), and downloads the trust
list when its LastUpdateTime moved. The new certificate, key and trust list
reach the application's persist callback together. The GDS must be trusted
beforehand; user credentials are used only until the first certificate is
issued and are never stored. `examples/pull_agent.c` is a small command-line
application built on it:

```sh
pull_agent --gds opc.tcp://gds.example:4840 --trust ca.der --crl ca.crl \
    --app-uri urn:example:hmi3 --name "HMI 3" --dir /var/lib/hmi3/pki \
    --user installer --password-file /run/installer.pw   # first run
pull_agent --gds opc.tcp://gds.example:4840 --trust ca.der --crl ca.crl \
    --app-uri urn:example:hmi3 --name "HMI 3" --dir /var/lib/hmi3/pki   # renewals
```

## Code

| File | What |
| --- | --- |
| `src/client/gdsc_session.c` | Secure sessions: endpoint and policy choice, explicit trust, identities |
| `src/client/gdsc_push.c` | ServerConfiguration and TrustList methods on the device |
| `src/client/gdsc_gds.c` | GDS Directory and CertificateManager methods |
| `src/push/push_workflows.c` | The §7.7 order, ApplyChanges, and CancelChanges after an error |
| `src/push/push_engine.c` | The scheduler: due jobs, workers, looking at the device first |
| `src/push/push_sched.c` | Timing: renewal point, back-off, jitter (no I/O) |
| `src/push/push_rejected.c` | GetRejectedList results as DialogConditions |
| `src/server/gds_push_slot.c` | The replaceable scheduling slot and the push target list |
| `src/gdsctl/push_targets.c` | `gdsctl push-targets` |
| `src/push/push_setup.c` | Annex G.2 setup: state check, register, push, SecurityAdmin Role |
| `src/client/gdsc_pull_agent.c` | Annex G.1 pull agent for applications |
| `src/daemon/gdsadm_push.c` | `gdsadm apps register`, `gdsadm push now`, `gdsadm push setup` |
| `examples/pull_agent.c` | An application that embeds the pull agent |
| `tests/spec/test_spec_annex_g.c` | Annex G and Reverse Connect spec tests |
| `tests/spec/run_annex_g_vs_opengdsd.sh` | The same end to end with opengdsd |
| `tests/integration/test_push_flow.c` | Push engine against `push_test_server`: refusals, cancel, a full push |
| `tests/integration/test_push_engine.c` | The scheduler against `push_test_server`: renewal, trust list, rejected dialog, back-off, standby |
| `tests/integration/push/` | End to end: opengdsd, then `gdsadm push now`, then `push_test_server` |
