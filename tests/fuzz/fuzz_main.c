/* OpenGDS fuzz targets - corpus replay driver for builds without libFuzzer
 * (-DOPENGDS_FUZZ=OFF). Runs every file given on the command line, and every
 * regular file in every directory given, through LLVMFuzzerTestOneInput.
 * Fails if it ran no input at all, so an empty corpus is noticed.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/limits.h"
#include "fuzz.h"
#include "common/banned.h"

/* At least every input limit in limits.h */
#define FUZZ_MAX_INPUT GDS_MAX_TRUSTLIST_SIZE

/* One directory entry name (NAME_MAX is 255 on Linux) */
typedef struct {
    char name[256];
} entry;

static int cmp_entries(const void *a, const void *b) {
    const entry *x = a;
    const entry *y = b;
    return strcmp(x->name, y->name);
}

static gds_status run_file(const char *path, size_t *runs) {
    gds_buf b = {0};
    gds_status r = gds_file_read(path, FUZZ_MAX_INPUT, &b);
    if(r != GDS_OK)
        return r;
    printf("%s\n", path);
    (void)LLVMFuzzerTestOneInput(b.data, b.len);
    gds_buf_free(&b);
    (*runs)++;
    return GDS_OK;
}

/* Entries of dir (no dot files), sorted so runs repeat. *out is malloc'd. */
static gds_status list_dir(const char *dir, entry **out, size_t *nOut) {
    *out = NULL;
    *nOut = 0;
    DIR *d = opendir(dir);
    if(!d)
        return GDS_EIO;
    entry *list = NULL;
    size_t n = 0, cap = 0;
    gds_status r = GDS_OK;
    const struct dirent *e;
    while(r == GDS_OK && (e = readdir(d)) != NULL) {
        if(e->d_name[0] == '.')
            continue;
        if(n == cap) {
            size_t nc = cap ? cap * 2 : 16;
            entry *nl = realloc(list, nc * sizeof(*list));
            if(!nl) {
                r = GDS_ENOMEM;
                break;
            }
            list = nl;
            cap = nc;
        }
        r = gds_path(list[n].name, sizeof(list[n].name), "%s", e->d_name);
        if(r == GDS_OK)
            n++;
    }
    closedir(d);
    if(n > 1)
        qsort(list, n, sizeof(*list), cmp_entries);
    *out = list;
    *nOut = n;
    return r;
}

static gds_status run_dir(const char *dir, size_t *runs) {
    entry *list = NULL;
    size_t n = 0;
    gds_status r = list_dir(dir, &list, &n);
    for(size_t i = 0; i < n && r == GDS_OK; i++) {
        char path[GDS_MAX_PATH];
        struct stat sb;
        r = gds_path(path, sizeof(path), "%s/%s", dir, list[i].name);
        if(r == GDS_OK && stat(path, &sb) == 0 && S_ISREG(sb.st_mode))
            r = run_file(path, runs);
    }
    free(list);
    return r;
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <corpus file or directory>...\n", argv[0]);
        return 2;
    }
    if(LLVMFuzzerInitialize(&argc, &argv) != 0)
        return 1;
    size_t runs = 0;
    for(int i = 1; i < argc; i++) {
        struct stat sb;
        gds_status r = GDS_ENOTFOUND;
        if(stat(argv[i], &sb) == 0)
            r = S_ISDIR(sb.st_mode) ? run_dir(argv[i], &runs) : run_file(argv[i], &runs);
        if(r != GDS_OK) {
            fprintf(stderr, "%s: %s\n", argv[i], gds_status_name(r));
            return 1;
        }
    }
    if(runs == 0) {
        fprintf(stderr, "no inputs\n");
        return 1;
    }
    printf("%zu inputs replayed\n", runs);
    return 0;
}
