/* OpenGDS fuzz target: the users file parser (gds_users_load,
 * src/server/gds_access.h). The parser is only reachable through a path,
 * so each input is written to a private 0600 file and loaded from there.
 * A file it accepts must give at most GDS_MAX_USERS users with distinct,
 * well-formed names, grantable roles only and a bounded iteration count.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/limits.h"
#include "fuzz.h"
#include "gds_access.h"
#include "common/banned.h"

static char usersPath[GDS_MAX_PATH];
static unsigned allRoles;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    char dir[GDS_MAX_PATH];
    gds_status r = fuzz_tmpdir(dir, sizeof(dir));
    if(r == GDS_OK)
        r = gds_path(usersPath, sizeof(usersPath), "%s/users", dir);
    if(r != GDS_OK) {
        fprintf(stderr, "fuzz_users: fixture: %s\n", gds_status_name(r));
        return 1;
    }
    size_t n = 0;
    const gds_role_info *t = gds_role_table(&n);
    for(size_t i = 0; i < n; i++)
        allRoles |= t[i].bit;
    return 0;
}

static bool write_input(const uint8_t *data, size_t size) {
    int fd = open(usersPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if(fd < 0)
        return false;
    bool ok = true;
    for(size_t done = 0; ok && done < size;) {
        ssize_t n = write(fd, data + done, size - done);
        ok = n > 0;
        if(ok)
            done += (size_t)n;
    }
    return close(fd) == 0 && ok;
}

static bool name_ok(const char *name) {
    size_t n = strnlen(name, GDS_MAX_USER_NAME + 1);
    if(n == 0 || n > GDS_MAX_USER_NAME)
        return false;
    for(size_t i = 0; i < n; i++) {
        char c = name[i];
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-' || c == '@'))
            return false;
    }
    return true;
}

static void check_user(const gds_users *u, size_t i) {
    const gds_user *x = &u->users[i];
    GDS_ASSERT(name_ok(x->name));
    GDS_ASSERT((x->roles & ~allRoles) == 0);
    GDS_ASSERT(x->iterations > 0);
    for(size_t j = 0; j < i; j++)
        GDS_ASSERT(strcmp(u->users[j].name, x->name) != 0);
}

static void check_users(const gds_users *u) {
    GDS_ASSERT(u->n <= GDS_MAX_USERS);
    for(size_t i = 0; i < u->n; i++)
        check_user(u, i);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static gds_users users; /* large: kept off the stack */
    GDS_ASSERT(write_input(data, size));
    if(gds_users_load(usersPath, &users) == GDS_OK)
        check_users(&users);
    memset(&users, 0, sizeof(users));
    return 0;
}
