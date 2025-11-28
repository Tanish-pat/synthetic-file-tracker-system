// trace_fs.bpf.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Event structure for ring buffer */
struct fs_event {
    u64 ts_ns;
    u32 pid;
    char comm[16];
    u8 type;        // 1=openat, 2=close
    int fd;
    char filename[256];
};

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} r_buffer_fs SEC(".maps");

/*
Synthetic file blocks
- Key: filename (char[256])
- Value: 4096 bytes of synthetic file content.
- Used to replace what a read() syscall returns.
*/
struct fake_file_block {
    char data[4096];
};

/* Synthetic FS map: key = filename, value = content */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[256]);
    __type(value, struct fake_file_block);
    __uint(max_entries, 128);
} synthetic_fs SEC(".maps");

/*
- Tracks each ongoing read keyed by pid_tgid, valued by fd + user_buffer
- Ensures when the syscall exits, the program knows where to write the synthetic content.
*/
struct read_info {
    u64 buf_ptr;    // user buffer pointer
    int fd;         // file descriptor
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);          // pid_tgid
    __type(value, struct read_info);
    __uint(max_entries, 1024);
} read_buffers SEC(".maps");

/*
fd -> filename map
- Maps open file descriptors to filenames.
- Updated externally from user-space (not shown in this code).
- Needed to find which synthetic file to write for a given fd.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, char[256]);
    __uint(max_entries, 512);
} fd_to_path SEC(".maps");

/* ---------------- tracepoints ---------------- */

/*
openat
- Hooks sys_enter_openat.
- Reads the filename from userspace and logs an fs_event in a ring buffer.
- Ring buffer avoids expensive map lookups and can be read by a user-space program asynchronously
*/
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname_ptr = (const char *)ctx->args[1];
    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->type = 1;
    e->fd = -1;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), fname_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
close
- Hooks sys_enter_close.
- Logs the close event in the ring buffer.
- Deletes the fd mapping in fd_to_path to prevent stale entries.
*/
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx) {
    int fd = (int)ctx->args[0];

    struct fs_event *e = bpf_ringbuf_reserve(&r_buffer_fs, sizeof(*e), 0);
    if (e) {
        e->ts_ns = bpf_ktime_get_ns();
        e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        e->type = 2;
        e->fd = fd;
        e->filename[0] = '\0';
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&fd_to_path, &fd);
    return 0;
}

/* read enter */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_info info = {};
    info.fd = (int)ctx->args[0];
    info.buf_ptr = (u64)ctx->args[1];

    bpf_map_update_elem(&read_buffers, &pid_tgid, &info, BPF_ANY);
    return 0;
}

/* pread64 enter */
SEC("tracepoint/syscalls/sys_enter_pread64")
int trace_pread64_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_info info = {};
    info.fd = (int)ctx->args[0];
    info.buf_ptr = (u64)ctx->args[1];

    bpf_map_update_elem(&read_buffers, &pid_tgid, &info, BPF_ANY);
    return 0;
}

/* read exit handler */
static __always_inline int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_info *info = bpf_map_lookup_elem(&read_buffers, &pid_tgid);
    if (!info) return 0;

    long ret = (long)ctx->ret;
    if (ret <= 0) goto cleanup;

    int fd = info->fd;
    char *name_ptr = bpf_map_lookup_elem(&fd_to_path, &fd);
    if (!name_ptr) goto cleanup;

    char fname[256] = {};
    if (bpf_probe_read_kernel_str(fname, sizeof(fname), name_ptr) <= 0) goto cleanup;

    struct fake_file_block *blk = bpf_map_lookup_elem(&synthetic_fs, fname);
    size_t len = ret;
    if (len > sizeof(struct fake_file_block))
        len = sizeof(struct fake_file_block);

    if (!info->buf_ptr) goto cleanup;

    char zero[128] = {};
    size_t offset = 0;

    if (len <= 128) {
        bpf_probe_write_user((void *)info->buf_ptr, blk ? blk->data : zero, len);
        goto cleanup;
    }

    /* Only 128-byte chunks allowed */
    if (len >= 128) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 256) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 384) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 512) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 640) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 768) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 896) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1024) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1152) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1280) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1408) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1536) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1664) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1792) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 1920) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2048) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2176) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2304) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2432) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2560) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2688) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2816) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 2944) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3072) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3200) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3328) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3456) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3584) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3712) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3840) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len >= 3968) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, 128); offset += 128;
    if (len > 4096) bpf_probe_write_user((void *)(info->buf_ptr + offset), blk ? blk->data + offset : zero, len - offset);

cleanup:
    bpf_map_delete_elem(&read_buffers, &pid_tgid);
    return 0;
}

/* read exit */
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    return handle_read_exit(ctx);
}

/* pread64 exit */
SEC("tracepoint/syscalls/sys_exit_pread64")
int trace_pread64_exit(struct trace_event_raw_sys_exit *ctx) {
    return handle_read_exit(ctx);
}

char _license[] SEC("license") = "GPL";
