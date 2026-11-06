# 1. OPC Foundation trademarks and claims

**Question:** can the project use the names "OpenGDS", "OpenGDS Auditor" and "UASM", and the report wording "self-test, not OPC Foundation certification"? What must it avoid?

**Answer:** yes to all four, with the rules below. Not legal advice. Elias decided on 2026-11-06 that trademark use is not a concern, so this note is for reference only, with no lawyer review planned.

## What the Foundation owns

- The Foundation holds US registrations for the word marks **OPC**, **OPC UA**, **OPC FOUNDATION** and **CERTIFIED FOR COMPLIANCE OPC FOUNDATION**, among 14 US filings ([trademark portfolio](https://trademarkdir.com/owner/opc-foundation)). Its own site lists "OPC Foundation", its logo, the "OPC UA" logo "and other OPC Foundation logos and titles" as its marks ([Specifications Agreement of Use, section G](https://opcfoundation.org/license/specifications/1.15/)).
- Word marks such as "OPC UA CX™" and "OPC UA FX™" are also claimed ([OPC 20100 summary](https://opcfoundation.org/developer-tools/documents/view/379/)).
- The governing document is **OPC 20100 Trademark Guideline, v1.00, 2026-03-02**. It covers organization logos ("OPC Foundation® Member"), technology logos ("OPC UA®") and certification logos, and "applies to all communication channels" ([summary page](https://opcfoundation.org/developer-tools/documents/view/379/)). The full text needs a login, so this note relies on the agreements below.

## Rules from the Foundation's agreements

From the [Specifications Agreement of Use](https://opcfoundation.org/license/specifications/1.15/), which everyone who downloads Part 12 accepts:

- "The OPC Foundation is the sole entity that may perform Specification certification testing."
- The agreement grants no right to use certification marks or trademarks.
- A product may claim compliance or conformance only if it meets the certification requirements. "Products that do not meet these requirements may claim only that the product was based on the Specifications."
- No trademark may be used "without prior written permission".

The [CTT Agreement of Use](https://opcfoundation.org/license/ctt/1.1/) repeats the compliance rule, says certification marks need written approval, and forbids publishing CTT results to third parties without the Foundation's approval.

The [UA Logo licence](https://opcfoundation.org/wp-content/uploads/2017/02/OPC-Logo-Member-Product-Application-and-Logo-License-digital.pdf) (free, for UA Logo members) lets a product show the OPC UA logo only after written approval per product, with the ® symbol, and records a test status per product: Certified, Self-tested, Interoperability Tested or Not Tested. So "self-tested" is a status the Foundation itself recognises, distinct from "certified".

open62541 shows the accepted pattern: it says only its reference server is "OPC Foundation Certified", that applications built on it are not, and that the certification logo is a Foundation trademark used with permission ([open62541 certification page](https://open62541.org/certification)).

## The names

| Name | Contains a Foundation mark? | Other conflicts found | Verdict |
|---|---|---|---|
| OpenGDS | No. "GDS" is a Part 12 term, not a registered mark in the portfolio above. | Two unrelated projects: [OpenGDS](https://github.com/ODTBuilder/OpenGDS-DS), a Korean geospatial toolset, archived in January 2021, and [OpenGDS.org](https://sourceforge.net/projects/opengdsorg), airline seating charts, last updated 2013. | Usable. Different fields and both dormant. Do a trademark register search (EUIPO, USPTO, WIPO) in class 9 and 42 before filing. |
| OpenGDS Auditor (`gdsaudit`) | No | None found | Usable. Keep "OPC" out of it, as planned. |
| UASM | No. "UA" alone is not in the portfolio; "OPC UA" is. | [UASM](https://github.com/Terraspace/UASM), a free MASM-compatible assembler, packaged in [MSYS2](https://packages.msys2.org/package/mingw-w64-ucrt-x86_64-uasm), [Arch](https://pkgdex.org/arch-linux/rolling/x86_64/extra/uasm-2.57.rpm.html), [openSUSE](https://build.opensuse.org/projects/home:bmwiedemann:reproducible:distribution:ring1/packages/uasm/files/uasm.spec?expand=0) and [Gentoo](https://gpo.zugaina.org/AJAX/Ebuild/55140443/View). | **Rename before public use.** No trademark clash with the Foundation, but a developer tool with the same name owns the search results and weakens any filing. |

## Wording to use and to avoid

| Use | Avoid |
|---|---|
| "implements OPC 10000-12 (OPC UA Part 12)", "an OPC UA Global Discovery Server", "based on the OPC UA specifications" | "OPC UA compliant", "conformant", "certified", "OPC-approved", "official" |
| "self-test, not OPC Foundation certification" on every Auditor report | "pass" next to the Foundation's name or logo; "certification", "pre-certified" or "CTT replacement" |
| "results map to ConformanceUnits" | Quoting or publishing CTT results without the Foundation's written approval |
| Plain text "OPC UA" with ® on first mention in prose (for example "OPC UA®") | Any Foundation logo, the "Certified for Compliance" mark, or "OPC" in a product name, logo, domain or package name |
| A trademark notice in the README and reports: "OPC UA and OPC Foundation are trademarks of the OPC Foundation. OpenGDS is not affiliated with or endorsed by the OPC Foundation." | Implying endorsement, partnership or membership before joining |

The Auditor preset planned as "pre-certification" is renamed "preparation for certification" (decided 2026-11-06).

