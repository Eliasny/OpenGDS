# OpenGDS

OpenGDS is an open-source OPC UA Global Discovery Server (OPC 10000-12) written in C on
[open62541](https://github.com/open62541/open62541) v1.5.10. It covers the application
directory, pull and push certificate management, trust lists, a built-in CA, roles,
approvals and audit, using only standard OPC UA. A stable C plugin API lets other
products extend it without forking.

The repository also holds the OpenGDS Auditor (`tools/auditor/`), a free Part 12 test tool
for GDS-ready servers, pull clients and GDSs. Its results are a self-test, not OPC
Foundation certification.

Status: early development. The architecture and security rules are in `docs/architecture.md`.

License: [MPL 2.0](LICENSE). Contributions use DCO sign-off (`git commit -s`).
