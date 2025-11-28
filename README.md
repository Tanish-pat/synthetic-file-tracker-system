# synthetic-file-tracker-system

SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

A userspace + eBPF system that provides a synthetic in-memory file store and a small interactive loader/monitor (`trace_fs`) to exercise and observe synthetic file activity via BPF tracepoints and maps.

* [Overview](#overview)
* [To Build](#build)
* [To Run](#run)
* [Program: trace_fs](#program-trace_fs)

---

## Overview

`trace_fs` demonstrates how eBPF maps and tracepoints can be used to present synthetic file contents to userland readers. The userspace loader loads the BPF skeleton, attaches tracepoint handlers for filesystem syscalls, and provides an interactive console to create, update, and inspect synthetic file entries stored in a pinned BPF map.

Examples were developed and tested on modern Ubuntu releases; this project uses libbpf and clang/LLVM for BPF compilation.

---

## To Build

### Dependencies

You need a recent Linux kernel (BTF/CO-RE support) and the following packages:

* clang and llvm (recommended recent versions)
* zlib / libelf / libbfd
* build-essential / make

On Debian/Ubuntu-like systems:

```bash
sudo apt install build-essential clang llvm libelf1 libelf-dev zlib1g-dev libbfd-dev libcap-dev linux-tools-common linux-tools-generic
```

### Build steps

The repository contains `libbpf` and `bpftool` subtrees used for building local artifacts.

From the project root:

```bash
cd src
make
```

Notes:

* The Makefile builds `trace_fs` and its BPF objects via clang + bpftool.
* If `vmlinux.h` for your architecture is missing, create it with `bpftool`:

```bash
cd tools
./bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../vmlinux/<arch>/vmlinux.h
```

Built binaries and intermediate artifacts are placed under `.output/` and the `src/` directory (the `trace_fs` loader binary appears in `src/`).

---

## To Run

`trace_fs` requires root to attach eBPF programs and pin maps. Basic flow:

1. (Optional) Ensure BPF filesystem is available for pinning:

```bash
sudo mount -t bpf bpffs /sys/fs/bpf || true
```

2. From `src/` run the loader:

```bash
sudo ./trace_fs
```

3. The loader is interactive. Supported commands:

* `t` — print the current synthetic tree (user-space bookkeeping)
* `o <path>` — open a path (adds an fd mapping and, if enabled, initializes a synthetic entry)
* `c <fd>` — close fd and remove mappings
* `w <fd>` — write synthetic content for the fd (enter content; terminate with a single line containing `.`)
* `r <fd>` — perform a read on the real fd (BPF handler will attempt to overwrite returned data with synthetic content)
* `q` — quit

On exit the loader prompts whether to pin the synthetic map under `/sys/fs/bpf/trace_fs/synthetic_fs` for reuse by future runs.

---

## Program: trace_fs

`trace_fs` is the single application in this repository. Key behaviors:

* BPF side (tracepoint handlers):

  * Hooks `sys_enter_openat`, `sys_enter_close`, `sys_enter_read`, `sys_enter_pread64` and their exits.
  * Emits small `fs_event` records into a ring buffer for opens/closes.
  * Maintains a pinned hash map `synthetic_fs` keyed by filename (`char[256]`) with values containing up to 4096 bytes of synthetic content.
  * Tracks in-flight reads (`read_buffers`) to know the user buffer pointer and file descriptor on syscall exit, then writes synthetic content into user buffers in 128-byte chunks using `bpf_probe_write_user` when a synthetic entry exists for the opened path.
  * Uses a BPF map `fd_to_path` (updated by userspace) to map fds → filename so the BPF program can identify which synthetic content to present during reads.

* Userspace loader (`trace_fs`):

  * Loads the BPF skeleton and attaches programs.
  * Creates a ring buffer consumer to print open/close events emitted by the BPF program.
  * Maintains in-memory bookkeeping of synthetic entries and an fd→path table; it updates the `fd_to_path` BPF map when files are opened/closed.
  * Provides interactive commands to create/update synthetic file content (which is written into the `synthetic_fs` map).
  * Optionally pins the `synthetic_fs` map for reuse across runs (pins to `/sys/fs/bpf/trace_fs/synthetic_fs`).

### Internals / Data layout

* `synthetic_fs` map: key `char[256]`, value `struct fake_file_block { char data[4096]; }`.
* `read_buffers` map: key `pid_tgid` (u64), value `{ buf_ptr, fd }`.
* `fd_to_path` map: key `int` (fd), value `char[256]`.

The loader populates `fd_to_path` so the BPF program can locate the synthetic content for a given fd during read exits.

---

## Security and Notes

* Building and running `trace_fs` requires root privileges and knowledge of eBPF workflows. Use on systems you control.
* `trace_fs` demonstrates techniques for presenting synthetic data to userland readers; exercise caution and do not deploy in production without a clear, legitimate purpose and appropriate safeguards.
* The project uses libbpf and bpftool from the repository subtree to ensure consistent builds.

---

