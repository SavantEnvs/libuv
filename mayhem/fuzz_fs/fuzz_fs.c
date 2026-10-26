/*
 * Fuzz target for libuv's filesystem API (uv_fs_*). The input is a script of operations run
 * against a private scratch directory under $TMPDIR (wiped after every input): open/close,
 * read/write/pread/pwrite, truncate, sync, stat family, rename/link/symlink/unlink, mkdir/rmdir,
 * scandir and opendir/readdir, readlink/realpath, copyfile, sendfile, access/chmod/chown/utime,
 * mkdtemp/mkstemp and statfs. Each operation runs either synchronously or through the threadpool
 * (the loop is drained right after submission so results stay deterministic).
 *
 * Paths are built from a small pool of relative names plus sanitized fuzz-chosen components (no
 * '/', never "." or ".."), and symlink targets come from the same pool, so nothing can leave
 * the scratch directory.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "uv.h"
#include "reader.h"

#define NFD 4
#define BUFSZ 1024

static uv_loop_t loop;
static char base[PATH_MAX];
static char root[PATH_MAX + 8];
static uv_file fds[NFD];
static uv_dir_t *dir;
static uv_dirent_t dirents[4];

typedef struct {
    uv_fs_t req;
    char buf[BUFSZ];
    uv_buf_t iov[2];
} fsreq_t;

static const char *const pool[] = {"a", "b", "c", "d", "d/e", "d/f", "g", "h"};
#define NPOOL (sizeof(pool) / sizeof(pool[0]))

static void consume(uv_fs_t *req) {
    switch (req->fs_type) {
    case UV_FS_SCANDIR: {
        uv_dirent_t ent;
        while (uv_fs_scandir_next(req, &ent) >= 0)
            (void)strlen(ent.name);
        break;
    }
    case UV_FS_STAT:
    case UV_FS_LSTAT:
    case UV_FS_FSTAT: {
        uv_stat_t *st = &req->statbuf;
        volatile uint64_t sink = st->st_size + st->st_mode + st->st_nlink + st->st_mtim.tv_sec;
        (void)sink;
        break;
    }
    case UV_FS_READLINK:
    case UV_FS_REALPATH:
        if (req->ptr)
            (void)strlen((const char *)req->ptr);
        break;
    case UV_FS_STATFS: {
        uv_statfs_t *sf = (uv_statfs_t *)req->ptr;
        if (sf)
            (void)(sf->f_bsize + sf->f_blocks);
        break;
    }
    case UV_FS_OPEN:
    case UV_FS_MKSTEMP:
        if (req->result >= 0) {
            uv_fs_t c;
            uv_fs_close(&loop, &c, (uv_file)req->result, NULL);
            uv_fs_req_cleanup(&c);
        }
        break;
    default:
        break;
    }
}

static void fs_done(uv_fs_t *req) {
    consume(req);
    uv_fs_req_cleanup(req);
    free(req);
}

static int do_path(char *out, rd_t *r) {
    uint8_t sel = rd_u8(r);
    if (sel % 3 != 2) {
        snprintf(out, PATH_MAX + 64, "%s/%s", root, pool[sel % NPOOL]);
        return 0;
    }
    char comp[24];
    size_t n = 1, got;
    comp[0] = 'n';
    const uint8_t *src = rd_bytes(r, rd_u8(r) % 16, &got);
    for (size_t i = 0; i < got; i++)
        comp[n++] = (src[i] == '/' || src[i] == 0) ? '_' : (char)src[i];
    comp[n] = 0;
    snprintf(out, PATH_MAX + 64, "%s/%s", root, comp);
    return 0;
}

/* Symlink target: a relative pool name or a scratch-dir absolute path. */
static void link_target(char *out, rd_t *r) {
    uint8_t sel = rd_u8(r);
    if (sel & 1)
        snprintf(out, PATH_MAX + 64, "%s", pool[(sel >> 1) % NPOOL]);
    else
        snprintf(out, PATH_MAX + 64, "%s/%s", root, pool[(sel >> 1) % NPOOL]);
}

static int slot_fd(rd_t *r) { return fds[rd_u8(r) % NFD]; }

static void store_fd(uv_file fd) {
    for (int i = 0; i < NFD; i++) {
        if (fds[i] < 0) {
            fds[i] = fd;
            return;
        }
    }
    uv_fs_t c;
    uv_fs_close(&loop, &c, fd, NULL);
    uv_fs_req_cleanup(&c);
}

static int rm_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb; (void)ftw;
    if (type == FTW_DP)
        rmdir(path);
    else
        unlink(path);
    return 0;
}

static void wipe(void) {
    nftw(root, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static void cleanup_base(void) {
    wipe();
    rmdir(base);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    const char *tmp = getenv("TMPDIR");
    snprintf(base, sizeof(base), "%s/uvfzfs-XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(base))
        return 1;
    snprintf(root, sizeof(root), "%s/w", base);
    atexit(cleanup_base);
    return 0;
}

static void run_op(uint8_t op, rd_t *r) {
    uint8_t flags = rd_u8(r);
    int async = flags & 1;
    char p1[PATH_MAX + 64], p2[PATH_MAX + 64];
    uv_fs_cb cb = async ? fs_done : NULL;
    fsreq_t *R = (fsreq_t *)calloc(1, sizeof(*R));
    if (!R)
        return;
    int rc = -1;
    int want_fd = 0;   /* sync open-like ops store their descriptor */

    switch (op % 34) {
    case 0: case 1: {
        do_path(p1, r);
        uint8_t fl = rd_u8(r), m = rd_u8(r);
        int acc = (fl & 3) == 3 ? O_RDWR : (fl & 3);
        int oflags = acc | ((fl & 4) ? O_CREAT : 0) | ((fl & 8) ? O_TRUNC : 0) |
                     ((fl & 16) ? O_APPEND : 0) | ((fl & 32) ? O_EXCL : 0) |
                     ((fl & 64) ? O_NOFOLLOW : 0) | ((fl & 128) ? O_DIRECTORY : 0);
        rc = uv_fs_open(&loop, &R->req, p1, oflags, (m & 0777) | 0600, cb);
        want_fd = 1;
        break;
    }
    case 2: {
        int fd = slot_fd(r);
        for (int i = 0; i < NFD; i++)
            if (fds[i] == fd && fd >= 0) {
                fds[i] = -1;
                break;
            }
        rc = uv_fs_close(&loop, &R->req, fd, cb);
        break;
    }
    case 3: case 4: {
        int fd = slot_fd(r);
        unsigned n = 1 + rd_u8(r) * 2u;
        int64_t off = (flags & 2) ? -1 : (int64_t)rd_u8(r) * 16;
        R->iov[0] = uv_buf_init(R->buf, n > BUFSZ ? BUFSZ : n);
        rc = uv_fs_read(&loop, &R->req, fd, R->iov, 1, off, cb);
        break;
    }
    case 5: case 6: case 7: {
        int fd = slot_fd(r);
        size_t got;
        uint8_t len = rd_u8(r);
        const uint8_t *src = rd_bytes(r, len, &got);
        int64_t off = (flags & 2) ? -1 : (int64_t)rd_u8(r) * 16;
        memcpy(R->buf, src, got);
        size_t half = got / 2;
        R->iov[0] = uv_buf_init(R->buf, (unsigned)half);
        R->iov[1] = uv_buf_init(R->buf + half, (unsigned)(got - half));
        rc = uv_fs_write(&loop, &R->req, fd, R->iov, 2, off, cb);
        break;
    }
    case 8: rc = uv_fs_ftruncate(&loop, &R->req, slot_fd(r), (int64_t)rd_u16(r) * 16, cb); break;
    case 9: rc = (flags & 2) ? uv_fs_fsync(&loop, &R->req, slot_fd(r), cb)
                             : uv_fs_fdatasync(&loop, &R->req, slot_fd(r), cb); break;
    case 10: rc = uv_fs_fstat(&loop, &R->req, slot_fd(r), cb); break;
    case 11: case 12: do_path(p1, r); rc = uv_fs_stat(&loop, &R->req, p1, cb); break;
    case 13: do_path(p1, r); rc = uv_fs_lstat(&loop, &R->req, p1, cb); break;
    case 14: do_path(p1, r); do_path(p2, r); rc = uv_fs_rename(&loop, &R->req, p1, p2, cb); break;
    case 15: case 16: do_path(p1, r); rc = uv_fs_unlink(&loop, &R->req, p1, cb); break;
    case 17: case 18: do_path(p1, r); rc = uv_fs_mkdir(&loop, &R->req, p1, (rd_u8(r) & 0777) | 0700, cb); break;
    case 19: do_path(p1, r); rc = uv_fs_rmdir(&loop, &R->req, p1, cb); break;
    case 20: do_path(p1, r); rc = uv_fs_scandir(&loop, &R->req, p1, 0, cb); break;
    case 21: do_path(p1, r); rc = uv_fs_readlink(&loop, &R->req, p1, cb); break;
    case 22: link_target(p1, r); do_path(p2, r); rc = uv_fs_symlink(&loop, &R->req, p1, p2, rd_u8(r) & 3, cb); break;
    case 23: do_path(p1, r); do_path(p2, r); rc = uv_fs_link(&loop, &R->req, p1, p2, cb); break;
    case 24: do_path(p1, r); rc = uv_fs_realpath(&loop, &R->req, p1, cb); break;
    case 25: do_path(p1, r); do_path(p2, r); rc = uv_fs_copyfile(&loop, &R->req, p1, p2, rd_u8(r) & 7, cb); break;
    case 26: {
        int out = slot_fd(r), in = slot_fd(r);
        int64_t off = (int64_t)rd_u8(r) * 8;
        rc = uv_fs_sendfile(&loop, &R->req, out, in, off, rd_u16(r), cb);
        break;
    }
    case 27: do_path(p1, r); rc = uv_fs_access(&loop, &R->req, p1, rd_u8(r) & 7, cb); break;
    case 28: do_path(p1, r); rc = uv_fs_chmod(&loop, &R->req, p1, (rd_u8(r) & 07777) | 0700, cb); break;
    case 29: rc = uv_fs_fchmod(&loop, &R->req, slot_fd(r), (rd_u8(r) & 0777) | 0600, cb); break;
    case 30: {
        double at = rd_u16(r) * 60.0, mt = rd_u16(r) * 60.0;
        switch (flags >> 1 & 3) {
        case 0: do_path(p1, r); rc = uv_fs_utime(&loop, &R->req, p1, at, mt, cb); break;
        case 1: rc = uv_fs_futime(&loop, &R->req, slot_fd(r), at, mt, cb); break;
        default: do_path(p1, r); rc = uv_fs_lutime(&loop, &R->req, p1, at, mt, cb); break;
        }
        break;
    }
    case 31:
        if (flags & 2) {
            snprintf(p1, sizeof(p1), "%s/tXXXXXX", root);
            rc = uv_fs_mkdtemp(&loop, &R->req, p1, cb);
        } else {
            snprintf(p1, sizeof(p1), "%s/sXXXXXX", root);
            rc = uv_fs_mkstemp(&loop, &R->req, p1, cb);
            want_fd = 1;
        }
        break;
    case 32:
        do_path(p1, r);
        if (flags & 2)
            rc = uv_fs_statfs(&loop, &R->req, p1, cb);
        else
            rc = uv_fs_chown(&loop, &R->req, p1, (uv_uid_t)-1, (uv_gid_t)-1, cb);
        break;
    default:
        /* Directory handles are synchronous-only: opendir / readdir / closedir. */
        async = 0;
        cb = NULL;
        if (dir == NULL) {
            do_path(p1, r);
            rc = uv_fs_opendir(&loop, &R->req, p1, NULL);
            if (rc == 0) {
                dir = (uv_dir_t *)R->req.ptr;
                dir->dirents = dirents;
                dir->nentries = sizeof(dirents) / sizeof(dirents[0]);
            }
        } else if (flags & 2) {
            dir->nentries = sizeof(dirents) / sizeof(dirents[0]);
            rc = uv_fs_readdir(&loop, &R->req, dir, NULL);
            for (ssize_t i = 0; i < R->req.result && i < (ssize_t)dir->nentries; i++)
                (void)strlen(dir->dirents[i].name);
        } else {
            uv_dir_t *d = dir;
            dir = NULL;
            rc = uv_fs_closedir(&loop, &R->req, d, NULL);
        }
        break;
    }

    if (async && rc == 0) {
        uv_run(&loop, UV_RUN_DEFAULT);
        return;
    }
    if (!async && rc >= 0) {
        if (want_fd)
            store_fd((uv_file)R->req.result);
        else
            consume(&R->req);
    }
    uv_fs_req_cleanup(&R->req);
    free(R);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return -1;
    rd_t r = {data, size};
    if (uv_loop_init(&loop) != 0)
        return 0;
    for (int i = 0; i < NFD; i++)
        fds[i] = -1;
    dir = NULL;
    wipe();
    if (mkdir(root, 0700) != 0 && errno != EEXIST) {
        uv_loop_close(&loop);
        return 0;
    }
    mkdir(root, 0700);
    {
        char sub[PATH_MAX + 64];
        snprintf(sub, sizeof(sub), "%s/d", root);
        mkdir(sub, 0700);
    }

    int budget = 80;
    while (rd_more(&r) && budget-- > 0)
        run_op(rd_u8(&r), &r);

    if (dir) {
        uv_fs_t c;
        uv_fs_closedir(&loop, &c, dir, NULL);
        uv_fs_req_cleanup(&c);
        dir = NULL;
    }
    for (int i = 0; i < NFD; i++) {
        if (fds[i] >= 0) {
            uv_fs_t c;
            uv_fs_close(&loop, &c, fds[i], NULL);
            uv_fs_req_cleanup(&c);
        }
    }
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    wipe();
    return 0;
}
