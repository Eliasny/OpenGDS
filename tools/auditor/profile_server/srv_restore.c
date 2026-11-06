/* OpenGDS Auditor server profile: snapshot restore, the last line of every
 * run that changed the target (docs/auditor/README.md, "Safety, snapshot and
 * restore"). It has its own verdict. SPDX-License-Identifier: MPL-2.0 */
#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

static void t_restore(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->snapTaken) {
        ga_pass(ctx, "no test changed the target; nothing to restore");
        return;
    }
    char why[384];
    UA_StatusCode r = st_restore(t, why, sizeof(why));
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "restore incomplete: %s", why);
    else if(why[0])
        ga_warn(ctx, "%s", why); /* SRV-UPD-09, selected by name */
    else
        ga_pass(ctx, "trust list and certificate of the snapshot pushed back and applied");
}

const ga_test srv_restore_tests[] = {
    {"SRV-RESTORE", "README Safety", "The snapshot taken before the first write is restored",
     true, false, t_restore},
};
const size_t srv_restore_count = GDS_ARRAY_SIZE(srv_restore_tests);
