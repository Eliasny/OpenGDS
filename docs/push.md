# Pushing certificates and trust lists to a device

OpenGDS manages devices that cannot pull their own certificates with the push model of OPC 10000-12 v1.05.07 §7.7. In the T2 tracer an administrator starts the push with `gdsadm push now`. The scheduler (`push_engine.c`) comes in W3.

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

## Code

| File | What |
| --- | --- |
| `src/client/gdsc_session.c` | Secure sessions: endpoint and policy choice, explicit trust, identities |
| `src/client/gdsc_push.c` | ServerConfiguration and TrustList methods on the device |
| `src/client/gdsc_gds.c` | GDS Directory and CertificateManager methods |
| `src/push/push_workflows.c` | The §7.7 order, ApplyChanges, and CancelChanges after an error |
| `src/daemon/gdsadm_push.c` | `gdsadm apps register`, `gdsadm push now` |
| `tests/integration/test_push_flow.c` | Push engine against `push_test_server`: refusals, cancel, a full push |
| `tests/integration/push/` | End to end: opengdsd, then `gdsadm push now`, then `push_test_server` |
