# Research

Desk research on the open risks in the project context and the Auditor plan, done in week 1. Every claim links to a public source, read on 2026-11-06. This is not legal advice: the trademark note lists what a short lawyer review should confirm.

| Note | Question | Short answer |
|---|---|---|
| [1. OPC trademarks and claims](01-opc-trademarks-and-claims.md) | Can we use "OpenGDS", "OpenGDS Auditor" and "UASM", and the wording "self-test, not OPC Foundation certification"? | Yes. None of the names contains a Foundation mark. "OPC" and "OPC UA" are registered marks, so keep them out of names, logos and domains, and use them only to describe what the software implements. Never say "compliant", "conformant" or "certified" without a certificate. "UASM" collides with a well-known open-source assembler, and "OpenGDS" with two dormant geospatial and airline projects. |
| [2. GDS landscape](02-gds-landscape.md) | Who else ships a GDS, and does anyone offer a free behavioural Part 12 tester? | Fraunhofer IOSB still lists its open62541 GDS as "open source release planned", with no date. Commercial GDSs: Unified Automation UaGDS (also resold as a Siemens Industrial Edge app) and Systerel SGDS. Free: the OPC Foundation's MIT-licensed .NET GDS, and Trustpoint (MIT) as a push-only certificate manager. No free behavioural Part 12 tester was found. |
| [3. CTT access](03-ctt-access.md) | How do we get the Compliance Test Tool, and what does it cost? | Startup membership ($500 a year, companies under $2M sales) includes the CTT free. Corporate D ($3,000) adds a 50% certification lab discount. Non-members can only buy CTT use as part of a certification service, priced by quote. |

## What changes in the plans

1. **Join the OPC Foundation as a Startup member** ($500 a year) once the company that will own the OpenGDS trademark exists. It brings the CTT, which now automates GDS client and server tests, for OpenGDS 1.0 and Auditor reference runs. Step up to Corporate D before certifying UASM to get the lab discount. This closes the "CTT access" open decision in the project context.
2. **Rename UASM before any public use.** UASM is a MASM-compatible assembler packaged in Arch, MSYS2, openSUSE and Gentoo. Sharing the name with a developer tool makes search and any trademark filing harder. "OpenGDS" is usable: the two projects using it are dormant and in other fields.
3. **Use "OpenGDS Auditor"**, never a name with "OPC" or "OPC UA" in it. Keep the planned report line, and use the wording rules in note 1 on reports, the README and the website.
4. **Contact Fraunhofer IOSB early**, as the plan already says. Their GDS is still unreleased, so OpenGDS can be first with an open, MPL-licensed C GDS, but a release from them would compete head on.
5. **Download and read OPC 20100 Trademark Guideline v1.00 (2026-03-02)** before Auditor 1.0. It needs a free OPC Foundation login, so this research could read only its summary.
