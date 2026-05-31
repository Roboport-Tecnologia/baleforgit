// C ABI exported by the bale-mount-ffi Rust staticlib. Imported into the Swift
// FSKit extension via a bridging header / module map.
#ifndef BALE_MOUNT_H
#define BALE_MOUNT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> // off_t-ish; we use fixed-width below

#ifdef __cplusplus
extern "C" {
#endif

#define BALE_ROOT_INODE 1u

typedef struct BaleVfs BaleVfs; // opaque

typedef struct {
    int kind; // 0 = dir, 1 = file
    uint64_t size;
    uint64_t inode;
} BaleAttr;

typedef void (*BaleDirCb)(void *ctx, const char *name, uint64_t inode, int kind);

BaleVfs *bale_vfs_open(const char *repo_path, const char *rev);
void bale_vfs_free(BaleVfs *vfs);

int bale_vfs_getattr(BaleVfs *vfs, uint64_t inode, BaleAttr *out);
uint64_t bale_vfs_lookup(BaleVfs *vfs, uint64_t parent, const char *name);
int bale_vfs_readdir(BaleVfs *vfs, uint64_t dir, BaleDirCb cb, void *ctx);

uint64_t bale_vfs_open_file(BaleVfs *vfs, uint64_t inode);
intptr_t bale_vfs_read(BaleVfs *vfs, uint64_t fh, uint64_t offset, uint8_t *buf, size_t len);
void bale_vfs_close(BaleVfs *vfs, uint64_t fh);

const char *bale_vfs_last_error(void);

#ifdef __cplusplus
}
#endif

#endif // BALE_MOUNT_H
