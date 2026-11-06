/* OpenGDS - checked integer helpers.
 * SPDX-License-Identifier: MPL-2.0 */
#include "safeint.h"

#include <errno.h>
#include <stdlib.h>

#include "banned.h"

bool gds_parse_long(const char *s, long min, long max, long *out) {
    if(!s || !*s || !out)
        return false;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if(errno != 0 || !end || *end != '\0' || v < min || v > max)
        return false;
    *out = v;
    return true;
}
