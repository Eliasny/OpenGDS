/* OpenGDS - the few POSIX calls that differ on Windows.
 *
 * OpenGDS itself runs on Linux. The Auditor's headless binary is also built
 * for Windows (Auditor plan AT5, MinGW-w64), so the shared file helpers and
 * the Auditor go through these names. On POSIX they are the plain calls.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_PLATFORM_H
#define OPENGDS_COMMON_PLATFORM_H

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <direct.h>
#include <io.h>
#include <windows.h>

/* No symlinks to refuse (O_NOFOLLOW) and handles are not inherited unless
 * asked (O_NOINHERIT); every file is binary, never CRLF-translated. */
#define GDS_O_CLOEXEC (O_NOINHERIT | O_BINARY)
#define GDS_O_NOFOLLOW 0
/* NTFS ACLs, not mode bits, protect files: keep work folders in the
 * user's profile (docs/auditor/operator-guide.md). */
static inline int gds_mkdir(const char *path, int mode) {
    (void)mode;
    return _mkdir(path);
}
static inline int gds_fchmod(int fd, int mode) {
    (void)fd;
    (void)mode;
    return 0;
}
static inline int gds_fsync(int fd) {
    return _commit(fd);
}
/* rename() on Windows fails when the target exists */
static inline int gds_rename_replace(const char *from, const char *to) {
    return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
}
/* fopen mode without glibc's "e" (close-on-exec) */
#define GDS_FOPEN_WRITE_CLOEXEC "wN"
#define GDS_NULL_DEVICE "NUL"
/* read() and write() take an unsigned int count */
#define GDS_IO_CHUNK(n) ((unsigned)((n) > 0x40000000u ? 0x40000000u : (n)))
static inline bool gds_path_is_absolute(const char *p) {
    return p[0] == '/' || p[0] == '\\' ||
           (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':');
}
#else
#include <unistd.h>

#define GDS_O_CLOEXEC O_CLOEXEC
#define GDS_O_NOFOLLOW O_NOFOLLOW
static inline int gds_mkdir(const char *path, mode_t mode) {
    return mkdir(path, mode);
}
static inline int gds_fchmod(int fd, mode_t mode) {
    return fchmod(fd, mode);
}
static inline int gds_fsync(int fd) {
    return fsync(fd);
}
static inline int gds_rename_replace(const char *from, const char *to) {
    return rename(from, to);
}
#define GDS_FOPEN_WRITE_CLOEXEC "we"
#define GDS_NULL_DEVICE "/dev/null"
#define GDS_IO_CHUNK(n) (n)
static inline bool gds_path_is_absolute(const char *p) {
    return p[0] == '/';
}
#endif

#endif
