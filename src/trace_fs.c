// trace_fs.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include "common_um.h"
#include "common.h"

#include "trace_fs.skel.h"

#define MAX_SYN_FILES 512
#define MAX_PATH 256

struct fs_event {
    uint64_t ts_ns;
    uint32_t pid;
    char comm[16];
    uint8_t type;
    int fd;
    char filename[256];
};

struct fake_file_block {
    char data[4096];
};

static volatile sig_atomic_t exiting = 0;
static pid_t loader_pid = 0;
static bool erase_mode = false;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

/* simple in-memory bookkeeping (user-space) */
struct syn_entry {
    char path[MAX_PATH];
    int fd;
};
static struct syn_entry syn_tree[MAX_SYN_FILES];
static int syn_count = 0;

struct fd_map {
    int fd;
    char path[MAX_PATH];
};
static struct fd_map fd_table[MAX_SYN_FILES];
static int fd_count = 0;

static void trim(char *s)
{
    if (!s) return;
    size_t len = strlen(s);
    size_t i = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++;
    if (i) memmove(s, s + i, len - i + 1);
    len = strlen(s);
    while (len && (s[len-1] == ' ' || s[len-1] == '\t' || s[len-1] == '\r' || s[len-1] == '\n')) s[--len] = '\0';
}

static void add_syn_entry(const char *path, int fd)
{
    if (syn_count >= MAX_SYN_FILES) return;
    strncpy(syn_tree[syn_count].path, path, MAX_PATH - 1);
    syn_tree[syn_count].path[MAX_PATH-1] = '\0';
    syn_tree[syn_count].fd = fd;
    syn_count++;
}

static void remove_syn_entry(const char *path)
{
    for (int i = 0; i < syn_count; ++i) {
        if (strcmp(syn_tree[i].path, path) == 0) {
            syn_tree[i] = syn_tree[syn_count-1];
            syn_count--;
            return;
        }
    }
}

static void print_syn_tree(void)
{
    printf("/\n");
    for (int i = 0; i < syn_count; ++i) {
        const char *path = syn_tree[i].path;
        const char *slash = strrchr(path, '/');
        const char *name = slash ? slash + 1 : path;
        char dir[MAX_PATH] = {0};
        if (slash) {
            int len = slash - path;
            if (len > 0) {
                if (len >= (int)sizeof(dir)) len = sizeof(dir) - 1;
                memcpy(dir, path, len);
                dir[len] = '\0';
            }
        }
        printf("├─ %s/%s [fd=%d]\n", dir, name, syn_tree[i].fd);
    }
}

/* fd <-> path mapping */
static void add_fd_map(int fd, const char *path)
{
    if (fd_count >= MAX_SYN_FILES) return;
    fd_table[fd_count].fd = fd;
    strncpy(fd_table[fd_count].path, path, MAX_PATH - 1);
    fd_table[fd_count].path[MAX_PATH-1] = '\0';
    fd_count++;
}

static void remove_fd_map(int fd)
{
    for (int i = 0; i < fd_count; ++i) {
        if (fd_table[i].fd == fd) {
            fd_table[i] = fd_table[fd_count-1];
            fd_count--;
            return;
        }
    }
}

static const char *get_path_from_fd(int fd)
{
    for (int i = 0; i < fd_count; ++i)
        if (fd_table[i].fd == fd)
            return fd_table[i].path;
    return NULL;
}

/* ring buffer callback */
static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    (void)len;
    struct fs_event *e = data;
    if (!e) return 0;
    if ((pid_t)e->pid != loader_pid) return 0;

    if (e->type == 1)
        printf("[SELF OPEN]  pid=%u comm=%s file=%s\n", e->pid, e->comm, e->filename);
    else if (e->type == 2)
        printf("[SELF CLOSE] pid=%u comm=%s fd=%d\n", e->pid, e->comm, e->fd);
    else
        printf("[SELF UNKNOWN] pid=%u comm=%s\n", e->pid, e->comm);

    return 0;
}

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    return mkdir(path, 0755);
}

int main(int argc, char **argv)
{
    struct trace_fs_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;
    int synthetic_map_fd = -1;
    int fd_to_path_map_fd = -1;
    const char *pin_path = "/sys/fs/bpf/trace_fs/synthetic_fs";

    loader_pid = getpid();
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* open skeleton */
    skel = trace_fs_bpf__open();
    if (!skel) { fprintf(stderr, "Failed to open BPF skeleton\n"); err=1; goto cleanup; }
    if (!setup()) exit(1);

    /*
     * Pin handling decision.
     * We only examine whether a pinned map exists here and ask user whether
     * to reuse or erase. Actual map copy (from pinned -> running map)
     * happens after trace_fs_bpf__load() so we copy into the live map.
     */
    int pinned_fd_probe = bpf_obj_get(pin_path);
    bool reuse = false;
    if (pinned_fd_probe >= 0) {
        printf("Pinned map exists at %s\n", pin_path);
        printf("Options: [r]euse / [e]rase and create new: ");
        char buf[64] = {};
        if (!fgets(buf, sizeof(buf), stdin)) buf[0] = '\0';
        trim(buf);
        if (buf[0] == 'r' || buf[0] == 'R') {
            reuse = true;
            close(pinned_fd_probe);
            pinned_fd_probe = -1;
        } else {
            /* erase: remove the pinned map now so subsequent runs start fresh */
            close(pinned_fd_probe);
            pinned_fd_probe = -1;
            if (unlink(pin_path) != 0 && errno != ENOENT) {
                fprintf(stderr, "Warning: failed to unlink existing pinned map: %s\n", strerror(errno));
            } else {
                printf("Erased pinned map %s\n", pin_path);
            }
            erase_mode = true;
        }
    }

    /* load & verify (maps are created by load) */
    err = trace_fs_bpf__load(skel);
    synthetic_map_fd = bpf_map__fd(skel->maps.synthetic_fs);
    fd_to_path_map_fd = bpf_map__fd(skel->maps.fd_to_path);
    if (err) { fprintf(stderr, "Failed to load BPF skeleton: %d\n", err); goto cleanup; }

    /* If reusing, copy pinned map contents into the new skel map now (after load) */
    if (reuse) {
        int pinned_fd2 = bpf_obj_get(pin_path);
        if (pinned_fd2 < 0) {
            fprintf(stderr, "Requested reuse but pinned map not present at %s\n", pin_path);
        } else {
            int skel_map_fd = synthetic_map_fd;
            if (skel_map_fd < 0) {
                fprintf(stderr, "Invalid skel synthetic map fd\n");
            } else {
                char key[MAX_PATH] = {};
                char next[MAX_PATH] = {};
                struct fake_file_block blk = {};

                /* iterate pinned map keys */
                if (bpf_map_get_next_key(pinned_fd2, NULL, key) == 0) {
                    for (;;) {
                        if (bpf_map_lookup_elem(pinned_fd2, key, &blk) == 0) {
                            if (bpf_map_update_elem(skel_map_fd, key, &blk, BPF_ANY) != 0) {
                                fprintf(stderr, "failed to copy key %s into skel map: %s\n",
                                        key, strerror(errno));
                            }
                        }
                        if (bpf_map_get_next_key(pinned_fd2, key, next) != 0)
                            break;
                        memcpy(key, next, sizeof(key));
                    }
                }
            }
            close(pinned_fd2);
        }
    } else {
        erase_mode = true;
        // clear fd_to_path map
        if (fd_to_path_map_fd >= 0) {
            for (int i = 0; i < fd_count; i++) {
                int fd = fd_table[i].fd;
                bpf_map_delete_elem(fd_to_path_map_fd, &fd);
            }
        }

    }

    /* attach */
    err = trace_fs_bpf__attach(skel);
    if (err){ fprintf(stderr,"Failed to attach BPF programs\n"); goto cleanup; }

    /* ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.r_buffer_fs), handle_event, NULL, NULL);
    if (!rb){ fprintf(stderr,"Failed to create ring buffer\n"); goto cleanup; }

    printf("Attached. Commands:\n"
           "  t -> tree\n"
           "  o <path> -> open\n"
           "  c <fd> -> close\n"
           "  w <fd> -> write\n"
           "  r <fd> -> read\n"
           "  q -> quit\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 50);
        if (err == -EINTR) break;
        if (err < 0) { fprintf(stderr,"ring buffer poll error: %d\n", err); break; }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval tv = {0,0};
        if (select(STDIN_FILENO+1,&fds,NULL,NULL,&tv)>0 && FD_ISSET(STDIN_FILENO,&fds)){
            char line[512] = {};
            if (!fgets(line,sizeof(line),stdin)){ exiting=1; break; }
            trim(line);
            if (line[0]=='\0') continue;

            if(strcmp(line,"q")==0) break;
            else if(strcmp(line,"t")==0) print_syn_tree();
            else if(strncmp(line,"o ",2)==0){
                char path[MAX_PATH];
                strncpy(path,line+2,MAX_PATH-1); path[MAX_PATH-1]='\0'; trim(path);
                if (strlen(path) == 0) { fprintf(stderr, "invalid path\n"); continue; }
                if (strlen(path) >= MAX_PATH) { fprintf(stderr, "path too long (max %d)\n", MAX_PATH-1); continue; }

                int fd = open(path, O_RDONLY);
                if (fd < 0) {
                    fprintf(stderr, "open failed: %s\n", strerror(errno));
                } else {
                    add_fd_map(fd, path);

                    /* Add to fd_to_path BPF map (use fixed-size value buffer) */
                    if (fd_to_path_map_fd >= 0) {
                        char val[MAX_PATH] = {};
                        strncpy(val, path, sizeof(val) - 1);
                        if (bpf_map_update_elem(fd_to_path_map_fd, &fd, val, BPF_ANY) != 0)
                            fprintf(stderr, "Failed to update fd_to_path map: %s\n", strerror(errno));
                    }

                    /* Don't auto-create zeroed synthetic entries here.
                     * Let 'w' create/update entries explicitly to avoid clobbering reused state. */
                    add_syn_entry(path, fd);
                    /* New: if erase_mode, initialize synthetic_fs with zeros */
                    if (erase_mode && synthetic_map_fd >= 0) {
                        struct fake_file_block zero_blk = {};
                        char key[MAX_PATH] = {};
                        strncpy(key, path, sizeof(key)-1);
                        if (bpf_map_update_elem(synthetic_map_fd, key, &zero_blk, BPF_ANY) != 0) {
                            fprintf(stderr, "Failed to initialize zero synthetic file for %s\n", path);
                        }
                    }
                    printf("Opened fd=%d for %s\n", fd, path);
                }
            }
            else if(strncmp(line,"c ",2)==0){
                int fd = atoi(line+2);
                const char *p = get_path_from_fd(fd);
                if(p) remove_syn_entry(p);
                remove_fd_map(fd);

                /* Remove from fd_to_path BPF map */
                if (fd_to_path_map_fd >= 0) {
                    if (bpf_map_delete_elem(fd_to_path_map_fd, &fd) != 0 && errno != ENOENT)
                        fprintf(stderr, "Failed to delete fd->path mapping: %s\n", strerror(errno));
                }

                if (close(fd) == 0) printf("Closed fd=%d\n", fd);
                else fprintf(stderr, "close(%d) failed: %s\n", fd, strerror(errno));
            }
            else if (strncmp(line, "w ", 2) == 0) {
                int fd = atoi(line + 2);
                const char *path = get_path_from_fd(fd);
                if (!path) { printf("File not open\n"); continue; }
                if (strlen(path) >= MAX_PATH) { fprintf(stderr, "internal: path too long\n"); continue; }

                printf("Enter content, end with single '.' line:\n");
                char content[4096];
                size_t pos = 0;
                while (1) {
                    char buf[512];
                    if (!fgets(buf, sizeof(buf), stdin)) break;
                    if (buf[0] == '.' && buf[1] == '\n') break;
                    size_t len = strlen(buf);
                    if (pos + len < sizeof(content) - 1) {
                        memcpy(content + pos, buf, len);
                        pos += len;
                    } else {
                        size_t take = (sizeof(content) - 1) - pos;
                        if (take) memcpy(content + pos, buf, take);
                        pos += take;
                        break;
                    }
                }
                content[pos] = '\0';

                struct fake_file_block blk;
                memset(&blk, 0, sizeof(blk));
                strncpy(blk.data, content, sizeof(blk.data) - 1);

                char key[MAX_PATH] = {};
                strncpy(key, path, sizeof(key)-1);

                if (synthetic_map_fd >= 0) {
                    if (bpf_map_update_elem(synthetic_map_fd, key, &blk, BPF_ANY) == 0)
                        printf("Written synthetic file %s [fd=%d]\n", path, fd);
                    else
                        fprintf(stderr, "Failed to write synthetic file: %s\n", strerror(errno));
                } else {
                    fprintf(stderr, "synthetic_map_fd invalid\n");
                }
            }
            else if (strncmp(line, "r ", 2) == 0) {
                int fd = atoi(line + 2);
                const char *path = get_path_from_fd(fd);
                if (!path) { printf("File not open\n"); continue; }
                char buf[4096];
                ssize_t n = read(fd, buf, sizeof(buf)-1);   // <<< REAL SYSTEM CALL
                if (n < 0) { perror("read"); continue; }
                buf[n] = '\0';  /* BPF tracepoint handler overwrites this buffer on successful synthetic lookup */
                printf("%s", buf);
            }
            else printf("unknown command\n");
        }
    }

    /* commit/persist or cleanup pinned map */
    printf("Keep pinned map for future runs? (y/n): ");
    char buf[32] = {};
    if (!fgets(buf, sizeof(buf), stdin)) buf[0] = '\0';
    trim(buf);

    if (buf[0] == 'y' || buf[0] == 'Y') {
        ensure_dir("/sys/fs/bpf/trace_fs");

        /* Remove old pinned map if present (ignore ENOENT) then pin the current skel map */
        unlink(pin_path); /* ignore errors */
        if (skel && skel->maps.synthetic_fs) {
            if (bpf_map__pin(skel->maps.synthetic_fs, pin_path) == 0)
                printf("Pinned updated synthetic_fs map at %s\n", pin_path);
            else
                fprintf(stderr, "Failed to pin updated map: %s\n", strerror(errno));
        } else {
            fprintf(stderr, "No skel map to pin\n");
        }
    } else {
        if (unlink(pin_path) == 0) printf("Pinned map deleted.\n");
        else printf("Pinned map (if any) left intact or deletion failed\n");
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    if (skel) trace_fs_bpf__destroy(skel);
    return err ? -err : 0;
}
