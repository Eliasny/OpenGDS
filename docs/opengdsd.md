# Running opengdsd

`opengdsd` is the OpenGDS server. It serves the GDS Directory, the
CertificateManager and the DefaultApplicationGroup trust list
(OPC 10000-12 §6 and §7) over OPC UA.

## Processes

| Process | Holds | Talks to |
|---|---|---|
| `opengdsd` | the store (read-write), its own certificate and key, user sessions | clients over OPC UA; `opengds-signer` over a socketpair |
| `opengds-signer` | the CA key (decision G1) | `opengdsd` only; the store read-only |

`opengdsd` starts the signer itself when `signer` is set in the configuration. A signing request carries only the request id. The signer reads the record and the CSR from the store itself, so it signs only what the store holds.

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

2. Store the CA key passphrase. Under systemd, use `LoadCredentialEncrypted=ca-passphrase:...` (see `packaging/systemd/opengds.service`). Otherwise use a 0600 file named in `ca_passphrase_file`. The passphrase is never passed on argv or in the environment.

3. Write `opengds.conf`. Every key is listed in `src/daemon/config.h`, and `packaging/opengds.conf.example` is an example.

On first start:
- the signer creates the CA (RSA 3072, SHA-256, 10 years, decision G6) in `ca_dir`;
- `opengdsd` registers itself in its own store and gets its certificate through the normal request path, stored in `data_dir/own/`.

The certificate is renewed when less than 30 days remain.

## Clients

Give clients the CA certificate `ca_dir/ca.der` and the CRL `ca_dir/ca.crl` so they can trust the GDS. A GDS client must never trust a GDS on first use.

Sessions run only over SignAndEncrypt. SecurityPolicy None is open only for FindServers and GetEndpoints.

## Inspecting a running GDS

```sh
gdsadm apps list --store /var/lib/opengds/opengds.db
gdsadm certs status --store /var/lib/opengds/opengds.db
```

`gdsadm` opens the store read-only and can be used while `opengdsd` runs.

## Redundancy

Primary/standby clustering is the UASM cluster plugin. It uses `gds_server_set_role()` and `gds_server_set_service_level()` (issue #14). A standalone `opengdsd` reports ServiceLevel 255.
