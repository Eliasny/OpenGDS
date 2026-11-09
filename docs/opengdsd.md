# Running opengdsd

`opengdsd` is the OpenGDS server. It serves the GDS Directory, the
CertificateManager and the DefaultApplicationGroup trust list
(OPC 10000-12 §6 and §7) over OPC UA.

## Processes

| Process | Holds | Talks to |
|---|---|---|
| `opengdsd` | the store (read-write), its own certificate and key, user sessions | clients over OPC UA; `opengds-signer` over a socketpair |
| `opengds-signer` | the CA key (decision G1) | `opengdsd` only; the store read-only |

There are two ways to run the signer:

- **Production, `signer_socket`:** systemd runs the signer as its own unit under the `opengds-ca` user (`packaging/systemd/opengds-signer.socket` and `opengds-signer@.service`). `opengdsd` connects to `/run/opengds/signer.sock`, which only `opengds-ca` and the `opengds` group can open. The signer holds the CA passphrase through `LoadCredentialEncrypted=`, so `opengdsd` never sees it. The signer reads the store read-only through its membership in the `opengds` group, so `opengdsd` keeps the store group-readable (umask 027).
- **Without systemd (containers), `signer_socket` with `opengds-signer --listen PATH`:** the signer creates a SOCK_SEQPACKET socket at PATH with mode 0660 and serves one `opengdsd` connection at a time, each until it closes. Put the socket in a directory that only the signer and `opengdsd` users can reach, such as a volume shared by the two containers. The signer reads its passphrase from `--passphrase-file`.
- **`signer`:** `opengdsd` starts the signer itself over a socketpair. This is simpler, but both processes run as the same user. A signing request carries only the request id. The signer reads the record and the CSR from the store itself, so it signs only what the store holds.

Without `signer`, the CA runs inside `opengdsd`. That mode is for development only, and the daemon warns about it at startup.

Once its socket, store and CA are open (with `--listen`: at the first connection, once `opengdsd` has created the store), the signer sandboxes itself (`src/common/sandbox.c`), on top of what the systemd unit applies:

- `PR_SET_NO_NEW_PRIVS`.
- Landlock: the CA directory read-write, the store's directory read-only (SQLite then maps its shared-memory file read-only), the passphrase file or `$CREDENTIALS_DIRECTORY` read-only, and nothing else. It also allows no TCP bind or connect and, on kernels with Landlock ABI 6, no signals or abstract sockets outside the process. On kernels without Landlock the signer logs a warning and goes on.
- seccomp: an allowlist of the system calls it uses. Any other call fails with EPERM. `execve`, `ptrace`, `socket`, `connect`, `bind`, `listen`, `bpf`, `keyctl`, `mount` and module loading kill the process, as does new executable memory.

`opengdsd` sandboxes itself the same way once it has started (store, CA or signer connection, own certificate), with a wider profile for the OPC UA server:

- Landlock: `data_dir` read-write, `ca_dir` read-write only with the in-process CA, the configuration and users files read-only, and `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/gai.conf` and `/etc/localtime` read-only. TCP bind is allowed only on `port`, and TCP connect is not allowed at all (`opengdsd` makes no outgoing connections; push runs in `gdsadm`).
- seccomp: the signer's allowlist plus sockets, epoll, timers and threads. `clone` is allowed only with `CLONE_THREAD`, so `fork` fails, and `clone3` answers ENOSYS so that libc falls back to `clone`. `ioctl` is limited to FIONBIO and FIONREAD. `execve`, `ptrace` and the others kill the process.

The `opengds-signer: sandbox:` and `opengdsd: sandbox:` log lines (`Landlock ABI N, seccomp on`) show what applied. seccomp needs libseccomp (2.5 or later) at build time. `-DOPENGDS_SECCOMP=ON` makes it required, and without it the build applies Landlock only. Builds with AddressSanitizer or ThreadSanitizer skip the sandbox.

## First start

1. Create the users file, mode 0600:

   ```sh
   gdsadm hash-password            # reads the password from stdin
   echo "admin DiscoveryAdmin,CertificateAuthorityAdmin,SecurityAdmin <credential>" > /etc/opengds/users
   ```

   - **DiscoveryAdmin** may register, update and unregister applications.
   - **CertificateAuthorityAdmin** may request certificates for any application.
   - **SecurityAdmin** may change the GDS's own certificate and trust lists.

   An application can always manage itself through a client certificate issued by this GDS (ApplicationSelfAdmin).

2. Store the CA key passphrase. Under systemd it belongs to the signer's unit: `systemd-creds encrypt --name=ca-passphrase - /etc/opengds/ca-passphrase.cred` (see `packaging/systemd/opengds-signer@.service`). Otherwise use a 0600 file named in `ca_passphrase_file`. The passphrase is never passed on argv or in the environment.

3. Write `opengds.conf`. Every key is listed in `src/daemon/config.h`, and `packaging/opengds.conf.example` is an example.

On first start:
- the signer creates the CA (RSA 3072, SHA-256, 10 years, decision G6) in `ca_dir`;
- `opengdsd` registers itself in its own store and gets its certificate through the normal request path, stored in `data_dir/own/`.

The certificate is renewed when less than 30 days remain.

## Clients

Give clients the CA certificate `ca_dir/ca.der` and the CRL `ca_dir/ca.crl` so they can trust the GDS. A GDS client must never trust a GDS on first use.

Sessions run only over SignAndEncrypt. SecurityPolicy None is open only for FindServers and GetEndpoints.

## Approving certificate requests

`approval` in the configuration decides which requests are approved on arrival:

| `approval` | Approved on arrival | Waits for an administrator |
|---|---|---|
| `renewals` (default) | a request from an application over a secure channel that uses its newest valid certificate of that group and type (the holder of the prior certificate) | every other request |
| `manual` | none | every request |
| `auto` | every request (test benches) | none |

A waiting request has state Pending. FinishRequest answers Bad_NothingToDo until the request is approved and signed, and Bad_RequestNotAllowed once it is rejected (OPC 10000-12 §7.9.6).

Each waiting request is a standard Part 9 DialogCondition under the `Approvals` object (`ns=1;s=Approvals`), with NodeId `ns=1;g=<RequestId>`. Its ResponseOptionSet is Approve (0) and Reject (1). A session with the RegistrationAuthorityAdmin role answers with Respond2 (or Respond), and every answer emits an AuditConditionRespondEventType. Subscribe to events on the Server object and call ConditionRefresh to see every waiting request. The store holds the truth: the dialogs are raised again when `opengdsd` restarts. At most 10,000 requests wait at once; beyond that StartSigningRequest answers Bad_ServerTooBusy.

From the GDS host:

```sh
gdsadm approvals list --store /var/lib/opengds/opengds.db        # request id and ApplicationUri
gdsadm approvals approve --url opc.tcp://gds.example.com:58810 --user approver \
    --password-file ~/.opengds-pw --trust /var/lib/opengds-signer/ca/ca.der \
    --crl /var/lib/opengds-signer/ca/ca.crl --comment "known device" REQUEST_ID
gdsadm approvals reject ...same options... REQUEST_ID
```

`list` reads the store; `approve` and `reject` call Respond2 over SignAndEncrypt as the named user, who needs the RegistrationAuthorityAdmin role in the users file. The password comes from a file, never the command line, and the GDS certificate is checked against the CA given with `--trust`.

## Key pairs generated by the GDS

StartNewKeyPairRequest (OPC 10000-12 §7.9.4) is for applications that cannot make their own key. The signer generates the key for the requested CertificateType (RSA 2048 for RsaSha256ApplicationCertificateType, the default; a P-256 or P-384 key for EccNistP256 and EccNistP384) and the CA on that curve signs its certificate (docs/ca.md, "ECC: one issuing CA per curve"). A type outside the group's CertificateTypes is Bad_InvalidArgument. PrivateKeyFormat is `PFX` or `PEM` (PKCS #8); any other value is Bad_InvalidArgument. With a PrivateKeyPassword (at most 256 bytes) the key is encrypted with AES-256 (the PFX also uses PBKDF2 with 600,000 iterations and a SHA-256 MAC); without one it is delivered unencrypted, over the encrypted session only. SubjectName and DomainNames are ignored: the application record decides both, as for StartSigningRequest.

These requests go through the same approval policy as signing requests. The password and the key are never written to disk. `opengdsd` keeps them in memory, the password until the key is generated and the key until FinishRequest returns it once. If `opengdsd` restarts, the node switches to standby, or nobody calls FinishRequest within a day, the request fails with Bad_RequestNotAllowed and the application starts again. At most 64 key pair requests are open at once; beyond that the method answers Bad_ServerTooBusy.

## Revoking certificates

A session with the CertificateAuthorityAdmin role calls RevokeCertificate (OPC 10000-12 §7.9.6) on the Directory object with the ApplicationId and the certificate. Bad_NotFound means the application is not registered; Bad_InvalidArgument means this GDS did not issue that certificate to that application. UnregisterApplication revokes every certificate of the application before it deletes the record (§6.5.8).

The store marks the certificate revoked first. Then `opengds-signer` puts its serial on a new CRL (CRL number + 1), and only if the store marks that serial revoked, so `opengdsd` cannot revoke a certificate on its own. Every trust list of the group carries the CA's CRL, so applications see the revocation at their next trust list update. Revoking again succeeds and changes nothing, so a call that failed at the signer can simply be repeated. A revoked certificate stays on the CRL; GetCertificateStatus then answers that an update is required.

With gdsadm, as a user with CertificateAuthorityAdmin (revoke) or DiscoveryAdmin (unregister):

```sh
gdsadm certs revoke urn:example:device --revoke-cert device-cert.der CONNECTION
gdsadm apps unregister urn:example:device CONNECTION
```

CONNECTION is the same as for `gdsadm push now`: `--gds URL --cert DER --key DER --trust DER [--crl DER] --user NAME --password-file FILE`.

## The application trust list

Every application that pulls its trust list from the GDS (GetTrustList, OPC 10000-12 §7.9.9) gets the trust list of the DefaultApplicationGroup. It always holds the GDS CA certificate and its current CRL. A user with CertificateAuthorityAdmin can add more entries with the standard TrustList methods (§7.8.2), for example a self-signed device certificate or another CA with its CRL:

- `AddCertificate` adds one trusted, non-CA certificate. Its issuer must already be in the list.
- `RemoveCertificate` takes the SHA-1 thumbprint. Removing a CA removes its CRLs, and is refused while another entry still needs it.
- `Open` with Write+EraseExisting (0x06), `Write`, then `CloseAndUpdate` replaces the lists named in SpecifiedLists. `Close` without `CloseAndUpdate` discards what was written.

Every change is validated first (structure, signatures, validity period, revocation) and refused as a whole if one entry fails. Copies of the GDS issuing CA certificates (RSA, P-256, P-384) and their CRLs in a written list are ignored, and those certificates cannot be removed. The entries are kept in the store, so they survive a restart and replicate with it. Each change moves `LastUpdateTime` and raises a TrustListUpdatedAuditEventType. Only one client can have the list open for writing, and a file handle unused for 60 seconds (`ActivityTimeout`) is closed. A store backend without trust list support (before store ABI minor 5) answers Bad_NotSupported.

## Audit events

`Server.Auditing` is TRUE: opengdsd raises the Part 12 audit events, each an AuditUpdateMethodEventType with MethodId, InputArguments, Status and the caller's user name as ClientUserId:

| Event | Raised by |
|---|---|
| ApplicationRegistrationChangedAuditEventType (§6.5.12) | RegisterApplication, UpdateApplication, UnregisterApplication |
| CertificateRequestedAuditEventType (§7.9.12) | StartSigningRequest, StartNewKeyPairRequest, accepted or refused; never with the PrivateKeyPassword |
| CertificateDeliveredAuditEventType (§7.9.13) | FinishRequest that returns a certificate |
| CertificateRevokedAuditEventType (§7.9.14) | RevokeCertificate |
| TrustListUpdatedAuditEventType (§7.8.2.1) | CloseAndUpdate, AddCertificate, RemoveCertificate |

Each event is written to the store's hash-chained audit log before it is raised, so every event a client sees is in the log. Only calls the session was allowed to make are audited: a call refused for its roles or security mode, or on a standby, leaves no record, so an unauthorised client cannot fill the log. Events are visible to SecurityAdmin and to the GDS role of the method (DiscoveryAdmin for the directory, CertificateAuthorityAdmin for certificates). A store backend without the audit log (before store ABI minor 1) raises none and `Server.Auditing` reads FALSE.

## Importing applications

`gdsadm apps import` registers many applications at once, as a user with DiscoveryAdmin. Each record is one standard RegisterApplication call (OPC 10000-12 §6.5.5), so the GDS checks it exactly as it checks any other registration.

```sh
gdsadm apps import plant.csv --dry-run      # check the file; nothing is sent
gdsadm apps import plant.csv CONNECTION
```

A CSV file (RFC 4180, UTF-8) starts with a header row that names its columns, in any order:

| Column | Required | Value |
|---|---|---|
| `ApplicationUri` | yes | the application's URI |
| `ApplicationName` | yes | its name |
| `ApplicationType` | yes | `Server`, `Client` or `ClientAndServer` |
| `ApplicationNameLocale` | no | the name's locale, default `en` |
| `ProductUri` | no | |
| `DiscoveryUrls` | Servers | URLs separated by spaces |
| `ServerCapabilities` | no | Annex D identifiers separated by spaces, e.g. `DA LDS` |

```csv
ApplicationUri,ApplicationName,ApplicationType,DiscoveryUrls,ServerCapabilities
urn:plant:press1,"Press 1, hall B",Server,opc.tcp://press1.plant:4840,DA
urn:plant:hmi,HMI,Client,,
```

A JSON file is `{"Applications": [...]}` with each element an ApplicationRecordDataType in the OPC UA JSON encoding (OPC 10000-6 §5.4), for example `{"ApplicationUri": "urn:plant:hmi", "ApplicationType": 1, "ApplicationNames": [{"Locale": "en", "Text": "HMI"}]}`. An ApplicationId in the file is ignored, because the GDS assigns it.

The report has one tab-separated line per record: the line number in the file (or the element number in JSON), the ApplicationUri, and `registered` with the new ApplicationId, `exists`, `invalid` or `failed` with the status code. A record whose ApplicationUri is registered already is left as it is, so an import can be run again after fixing the failed rows. The exit code is 1 when any record was invalid or failed. The file may hold at most 100,000 records and 16 MiB.

## Inspecting a running GDS

```sh
gdsadm apps list --store /var/lib/opengds/opengds.db
gdsadm certs status --store /var/lib/opengds/opengds.db
```

`gdsadm` opens the store read-only and can be used while `opengdsd` runs.

## Redundancy

Primary/standby clustering is the UASM cluster plugin. It uses `gds_server_set_role()` and `gds_server_set_service_level()` (issue #14). A standalone `opengdsd` reports ServiceLevel 255.
