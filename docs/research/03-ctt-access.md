# 3. CTT access and cost

**Question:** how can the project get the OPC Foundation Compliance Test Tool (UACTT), and at what cost?

## Membership options

From the [membership benefits page](https://opcfoundation.org/membership/benefits/), dues in USD per year:

| Tier | Who | Dues | CTT | Lab testing | Logos |
|---|---|---|---|---|---|
| **Startup** | Annual sales under $2M | **$500** | **Free** | Access, no discount listed | Member logo and OPC UA logo |
| Corporate D | Annual sales under $2M | $3,000 | Free | 50% discount | Member logo and OPC UA logo |
| Corporate C | $2M to $20M | $4,800 | Free | 50% discount | Both |
| Non-Voting | any | $900 | Bought as a service | Not listed | Both |
| End-User | any | $1,800 | Bought as a service | Not listed | Member logo only |
| UA Logo | any | $0 | Bought as a service | Access | OPC UA logo only |

Joining means signing the Foundation's bylaws, IP policy and NDA ([become a member](https://opcfoundation.org/membership/become-a-member/)). The IP policy should be read before joining, since OpenGDS is MPL 2.0 and contributions to OPC work groups carry licensing duties.

The page does not define the Startup criteria beyond sales under $2M. Check whether it has an age limit or needs a registered company: if so, it waits for the company decision in the project context.

## Without membership

- Non-members "can purchase the CTT as part of a certification service" ([OPC Foundation forum FAQ](https://opcfoundation.org/forum/opc-certification-and-interoperability-testing/faq-how-can-i-get-the-compliance-test-tools-ctts/)). The [purchase page](https://opcfoundation.org/certification/purchase-test-tool) needs a login and lists no prices.
- Certification testing is quoted per product after a registration form. Minimum lab time is 3 days for a server, 5 for a client and 2 for an information model ([lab costs page](https://opcfoundation.org/lab-registration/costs/)). No public price was found.

## Licence terms that affect the project

The [CTT Agreement of Use](https://opcfoundation.org/license/ctt/1.1/):

- one licence per developer, for "self-testing OPC enabled applications";
- no copying, redistribution or access by third parties, so CTT runs cannot go into OpenGDS's public CI or be offered to Auditor users;
- results may not be disclosed to third parties without the Foundation's written approval, so the Auditor docs must not publish CTT results side by side with Auditor results unless approved;
- no reverse engineering. The Auditor must be built from Part 12 itself, never from studying CTT scripts. Keep a note in the Auditor repo that no CTT material was used.

## Recommendation

Take **Startup membership** once a company exists, at $500 a year. It gives the CTT for OpenGDS 1.0 and for cross-checking Auditor verdicts privately. Move to **Corporate D** ($3,000) in the year UASM goes to the certification lab, where the 50% discount on a multi-day GDS test should pay for the difference. The paid service without membership costs more and only covers one certification run.
