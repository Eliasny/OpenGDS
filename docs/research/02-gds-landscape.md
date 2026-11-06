# 2. The GDS landscape

**Question:** who else ships an OPC UA GDS, what are Fraunhofer IOSB's plans for an open62541 GDS, and does anyone offer a free behavioural Part 12 tester?

## GDS implementations

| Product | Maker | Base | Licence | Scope | Status |
|---|---|---|---|---|---|
| [Global Discovery Server for OPC UA](https://iosb.fraunhofer.de/en/projects-and-products/global-discovery-server-for-opc-ua.html) | Fraunhofer IOSB | open62541 | Not stated. "An open source release is planned." | Directory, pull and push certificate management, admin over OPC UA, automatic registration, links to existing PKI | Shown at [SPS 2025](https://www.iosb.fraunhofer.de/en/events/2025/smart-production-solution-2025.html) as a service offer. No public code or release date found. |
| [OPC UA GDS server library](https://www.nuget.org/packages/OPCFoundation.NetStandard.Opc.Ua.Gds.Server/) and sample GDS | OPC Foundation | UA-.NETStandard, C# | [MIT](https://github.com/OPCFoundation/UA-.NETStandard) | Part 12 server classes with pluggable CA, application store and request store | Active: v2.0.1, 2026-10-12. A reference, not a supported product: no HA, HSM or appliance. |
| [UaGDS](https://www.unified-automation.com/products/ua-runtime-software/uagds.html) | Unified Automation | Own SDK | Commercial, price on request | Pull and push, built-in CA, security groups, approval workflow, configuration tool | Released since 2022 ([OPC marketplace](https://opcfoundation.org/?p=14678)); also listed as a [Siemens Industrial Edge app](https://ausschreibungstexte.siemens.com/tiplv/Data/English/Drive_Technology,_Automation_Technology/Industrial_Edge/Apps/Value_Adding_Apps/UaGDS_-_OPC_UA_Global_Discovery_and_Security/(LV_8AQEV1WKYBHMQ4J011SNG308CR)) (seen in search results; the page blocks automated reading). Unified Automation is presenting enterprise-PKI integration with ECOS ([Hannover Messe 2026](https://opcconnect.opcfoundation.org/2026/06/opc-foundation-hannover-messe-2026/)). |
| [SGDS](https://opcfoundation.org/products/view/scat/) | Systerel | S2OPC | Commercial, price not listed | Push and pull, Global Discovery and Certificate Mgmt 2017 Server profile | Listed on the OPC marketplace (2024). |
| [Trustpoint](https://trustpoint.readthedocs.io/en/latest/getting_started/faq.html) | achelos, asvin, Campus Schwarzwald, Hochschule Hamm-Lippstadt; BMBF funded | Python | MIT | Industrial PKI with an [OPC UA GDS push module](https://trustpoint.readthedocs.io/en/latest/autoapi/request/gds_push/index.html): pushes trust lists and certificates to servers | v1.0. A certificate manager, not a GDS: no directory, no pull. A possible partner rather than a rival. |
| Hobby projects | various | open62541 or .NET | mostly none | e.g. [opcua_gds_server](https://github.com/Caduardoo/opcua_gds_server) (2 commits), [GDSwithREST](https://github.com/romanett/GDSwithREST) (last push March 2024) | Not viable. |

### open62541 itself

open62541 implements only the **push target**: the [GDS Receiver driver](https://open62541.org/doc/master/driver_gds_receiver.html) adds ServerConfiguration, transactions and CSR creation to a server. It has no GDS and no pull client. In [issue #4583](https://github.com/open62541/open62541/issues/4583) the maintainers say the pull side is not being worked on, that "a group" is building a GDS on open62541, and that it needs hooks so a server can be a GDS counterpart without private API. That group is most likely Fraunhofer IOSB, whose staff include core open62541 maintainers (an inference; the issue does not name them).

### What this means for OpenGDS

- Nobody ships an open-source, production-grade GDS in C today. The .NET GDS is the only free, complete one, and it targets C# shops. OpenGDS's position holds, but the window depends on Fraunhofer's release.
- Fraunhofer's release is the main competitive risk: same library and same maintainers. Watch their product page and the open62541 repository.
- Trustpoint could use OpenGDS as its pull-side GDS, or OpenGDS could use Trustpoint as an external CA through the plugin API.
- UASM's commercial rivals are UaGDS and SGDS. Their public product pages, as read for this note, mention no primary/standby cluster, HSM support or Part 21 onboarding, which supports UASM's focus. Their manuals were not checked.

## Free behavioural Part 12 testers

| Tool | Behaviour tests for GDS? | Access |
|---|---|---|
| [UACTT](https://opcfoundation.org/products/view/uactt) | Yes. The December 2024 release added automated tests "for the entire range of GDS functionality" for servers and clients ([Compliance Corner, December 2024](https://opcconnect.opcfoundation.org/2024/12/compliance-corner-december-2024/)). | Members, or bought as part of a certification service (note 3) |
| [UACTT Lite](https://opcconnect.opcfoundation.org/2026/06/compliance-corner-june-2026/) | No. It compares a server's address space with released NodeSets. | Free |
| .NET GDS client samples, Trustpoint, vendor configuration tools | They exercise push or pull, but give no verdicts tied to clauses and do not inject faults | Free or bundled |

**No free behavioural Part 12 tester was found.** The Auditor's niche holds. The nearest free code is the .NET GDS samples and Trustpoint's push module, which a user could script into ad-hoc checks.
