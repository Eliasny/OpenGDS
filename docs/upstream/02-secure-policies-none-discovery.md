# Gap 2: the secure-only server config blocks discovery

**Status (2026-11-06):** reported upstream as
[open62541#6771](https://github.com/open62541/open62541/issues/6771) (open since
2024-10-15, no comments, no linked PR). In closed PR
[#7451](https://github.com/open62541/open62541/pull/7451), which documented the
secure-only helper, a reviewer suggested either keeping #None out entirely or
adding it with `securityPolicyNoneDiscoveryOnly` set. Master still leaves #None
out, and its test `setDefaultWithSecureSecurityPolicies_excludesNone` asserts
that. The `server_encryption` example adds #None by hand behind an
`--allowDiscovery` flag.

**Patch:** [patches/master/0002-secure-policies-none-discovery.patch](patches/master/0002-secure-policies-none-discovery.patch)
(backport, library part only: [patches/v1.5.10/0002-secure-policies-none-discovery.patch](patches/v1.5.10/0002-secure-policies-none-discovery.patch)).

## What goes wrong

`UA_ServerConfig_setDefaultWithSecureSecurityPolicies` adds no
SecurityPolicy#None. A client cannot open a #None channel, so GetEndpoints and
FindServers fail and the client never learns the endpoints or the server
certificate. A connection works only if the client already has the server
certificate ("direct" connect). Part 4, 5.4.1 says the discovery services need
no message security. For a GDS this matters twice: pull clients and the push
side both discover a server before any trust exists (Part 12).

OpenGDS works around this today: `mock_gds` calls
`UA_ServerConfig_addSecurityPolicyNone` and sets
`securityPolicyNoneDiscoveryOnly = true`.

## The fix

The helper adds #None at the end, after the endpoints and the access control
are set up, and sets `securityPolicyNoneDiscoveryOnly`. So:

- no #None endpoint is created (the endpoints list stays secure-only);
- no UserTokenPolicy refers to #None;
- on a #None channel the server answers only GetEndpoints, FindServers and
  FindServersOnNetwork, and rejects everything else with
  `BadSecurityPolicyRejected` (existing check in `ua_services.c`).

The header comment, the `server_encryption` example (its #None block is no
longer needed, and `--allowDiscovery` is still accepted as a no-op) and
`CHANGES.md` are updated.

**This changes default behaviour**, which is why it carries a CHANGES.md entry. Elias chose this over an opt-in (O1, 2026-11-06).
If the maintainers want to keep "no #None at all" as the default, the fallback
is an opt-in: keep the helper as it is and document the two lines (or add a
small `UA_ServerConfig_addSecurityPolicyNoneDiscoveryOnly()` helper). The draft
PR text says so, so they can pick.

## Tests

- `tests/encryption/check_server_config_default.c`: `excludesNone` becomes
  `noneForDiscoveryOnly`. It checks that #None is present once, the flag is set,
  and no endpoint or UserTokenPolicy uses #None. `withTrustLists` now expects
  no endpoint for the #None policy.
- New `tests/encryption/check_secure_policies_discovery.c`: a real server and a
  client that opens a #None channel directly. GetEndpoints works and returns
  only secure endpoints with the server certificate, FindServers works, and a
  CreateSession on the #None channel gets `BadSecurityPolicyRejected`.

Checked on open62541 master `24fc6b296` (OpenSSL 3.0):

| Run | Result |
|---|---|
| New tests without the library change | discovery test 0/3; config test fails `noneForDiscoveryOnly` and `withTrustLists` |
| New tests with the change | discovery test 3/3; config test 16/16 |
| `server_encryption.c` compiled with `-Wall -Wextra -Werror` | builds |
| v1.5.10 with the backport, discovery test ported | 3/3 |

## Draft comment on #6771

> Still present on master (24fc6b296): `UA_ServerConfig_setDefaultWithSecureSecurityPolicies` adds no #None, so GetEndpoints and FindServers cannot be called (Part 4, 5.4.1 requires them without message security). This blocks GDS pull and push clients, which discover a server before they trust it (Part 12). I have a fix that adds #None for the discovery services only (`securityPolicyNoneDiscoveryOnly`, no #None endpoint, no #None UserTokenPolicy), with tests, and will open a PR referencing this issue.

## Draft pull request

> **Title:** `fix(plugin): allow discovery over #None with the secure-only server config`
>
> **Problem.** `UA_ServerConfig_setDefaultWithSecureSecurityPolicies` adds no SecurityPolicy#None. A client therefore cannot call GetEndpoints or FindServers to learn the endpoints and the server certificate, although Part 4, 5.4.1 requires these services without message security. A connection is only possible if the client already knows the server certificate. This also breaks GDS pull and push clients, which discover a server before trusting it (Part 12). Fixes #6771.
>
> **Solution.** Add #None at the end of the helper, after the endpoints and the access control, and set `securityPolicyNoneDiscoveryOnly`. No #None endpoint and no #None UserTokenPolicy is created, and every non-discovery service on a #None channel is rejected with `BadSecurityPolicyRejected`, so every Session stays secured. This follows the second option discussed in #7451. The `server_encryption` example no longer adds #None itself.
>
> **Compatibility.** Behaviour change for users of the helper: a #None SecureChannel can now be opened for discovery. Documented in `CHANGES.md` and the header. If you prefer to keep "no #None" as the default, I can turn this into an opt-in helper instead.
>
> **Tests.** `check_server_config_default.c` (updated) and the new `check_secure_policies_discovery.c` (GetEndpoints and FindServers over #None succeed, CreateSession over #None is rejected). Both fail without the change and pass with it.
