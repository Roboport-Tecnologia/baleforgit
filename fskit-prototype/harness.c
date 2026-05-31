// Runtime proof of the FFI boundary: links the Rust staticlib and drives the
// VFS the way the FSKit FSVolume ops will (open → readdir → getattr → read).
// Stands in for the not-yet-runnable signed extension.
#include "include/bale_mount.h"
#include <stdio.h>
#include <string.h>

static void on_entry(void *ctx, const char *name, uint64_t inode, int kind) {
    (void)ctx;
    printf("  entry: %-12s inode=%llu kind=%s\n", name,
           (unsigned long long)inode, kind == 0 ? "dir" : "file");
}

int main(void) {
    BaleVfs *vfs = bale_vfs_open("/tmp/some/repo", "HEAD~1");
    if (!vfs) {
        printf("open failed: %s\n", bale_vfs_last_error());
        return 1;
    }

    printf("readdir(root):\n");
    bale_vfs_readdir(vfs, BALE_ROOT_INODE, on_entry, NULL);

    uint64_t hello = bale_vfs_lookup(vfs, BALE_ROOT_INODE, "hello.txt");
    printf("lookup hello.txt -> inode %llu\n", (unsigned long long)hello);

    BaleAttr a;
    if (bale_vfs_getattr(vfs, hello, &a) == 0)
        printf("getattr hello.txt: kind=%d size=%llu\n", a.kind, (unsigned long long)a.size);

    uint64_t fh = bale_vfs_open_file(vfs, hello);
    char buf[256];
    intptr_t n = bale_vfs_read(vfs, fh, 0, (uint8_t *)buf, sizeof buf);
    if (n >= 0) {
        printf("read %ld bytes:\n---\n%.*s---\n", (long)n, (int)n, buf);
    } else {
        printf("read failed: %ld (%s)\n", (long)n, bale_vfs_last_error());
    }
    bale_vfs_close(vfs, fh);

    // subdir + binary read
    uint64_t sub = bale_vfs_lookup(vfs, BALE_ROOT_INODE, "sub");
    printf("readdir(sub inode=%llu):\n", (unsigned long long)sub);
    bale_vfs_readdir(vfs, sub, on_entry, NULL);
    uint64_t world = bale_vfs_lookup(vfs, sub, "world.bin");
    uint64_t fh2 = bale_vfs_open_file(vfs, world);
    uint8_t bin[16];
    intptr_t n2 = bale_vfs_read(vfs, fh2, 250, bin, sizeof bin); // tail, partial
    printf("read world.bin@250 -> %ld bytes:", (long)n2);
    for (intptr_t i = 0; i < n2; i++) printf(" %02x", bin[i]);
    printf("\n");
    bale_vfs_close(vfs, fh2);

    // negative: missing name
    printf("lookup nope -> %llu (expect 0)\n",
           (unsigned long long)bale_vfs_lookup(vfs, BALE_ROOT_INODE, "nope"));

    bale_vfs_free(vfs);
    printf("OK\n");
    return 0;
}
