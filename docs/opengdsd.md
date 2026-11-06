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

## Revoking certificates

A session with the CertificateAuthorityAdmin role calls RevokeCertificate (OPC 10000-12 §7.9.6) on the Directory object with the ApplicationId and the certificate. Bad_NotFound means the application is not registered; Bad_InvalidArgument means this GDS did not issue that certificate to that application. UnregisterApplication revokes every certificate of the application before it deletes the record (§6.5.8).

The store marks the certificate revoked first. Then `opengds-signer` puts its serial on a new CRL (CRL number + 1), and only if the store marks that serial revoked, so `opengdsd` cannot revoke a certificate on its own. Every trust list of the group carries the CA's CRL, so applications see the revocation at their next trust list update. Revoking again succeeds and changes nothing, so a call that failed at the signer can simply be repeated. A revoked certificate stays on the CRL; GetCertificateStatus then answers that an update is required.

## Inspecting a running GDS

```sh
gdsadm apps list --store /var/lib/opengds/opengds.db
gdsadm certs status --store /var/lib/opengds/opengds.db
```

`gdsadm` opens the store read-only and can be used while `opengdsd` runs.

## Redundancy

Primary/standby clustering is the UASM cluster plugin. It uses `gds_server_set_role()` and `gds_server_set_service_level()` (issue #14). A standalone `opengdsd` reports ServiceLevel 255.
