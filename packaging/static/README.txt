OpenGDS Auditor (gdsaudit) for Linux, static build
==================================================

gdsaudit tests Global Discovery Servers, push-managed OPC UA Servers and
pull clients against OPC 10000-12. Its results are a self-test, not OPC
Foundation certification.

This is one static program: it needs no libraries and runs on any Linux
of its architecture (kernel 3.17 or newer), in a container too.

  ./gdsaudit server --url opc.tcp://plc:4840 --server-cert plc.der \
      --work ./w --report results/plc

The operator guide (docs/auditor/operator-guide.md in the source) covers
preparation, read-only and full runs, plan files and the reports.

Licences: OpenGDS and open62541 are MPL 2.0, OpenSSL is Apache 2.0 and
musl is MIT; the texts are in licenses/. Source:
https://github.com/Eliasny/OpenGDS
