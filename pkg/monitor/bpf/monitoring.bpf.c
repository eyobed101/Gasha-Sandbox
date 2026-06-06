// monitoring.bpf.c — eBPF kernel program for Gasha-Lab sandbox telemetry.
//
// Tracepoints attached:
//   sched/sched_process_exec     process creation + exec path
//   sched/sched_process_exit     process exit + cleanup
//   syscalls/sys_enter_openat    file open (read access detection)
//   syscalls/sys_exit_openat     file open return (get fd→path)
//   syscalls/sys_enter_write     file write (fd-based)
//   syscalls/sys_enter_unlinkat  file delete
//   syscalls/sys_enter_connect   outbound TCP/UDP connect
//   syscalls/sys_enter_ptrace    ptrace attach (Linux process injection)
//   syscalls/sys_enter_clone     fork/clone (child process tracking)
//
// Build:
//   clang -target bpf -O2 -Wall -g \
//     -I/usr/include/$(uname -m)-linux-gnu \
//     -c bpf/monitoring.bpf.c -o bpf/monitoring.bpf.o
//
//   Or via bpf2go (recommended for Go integration):
//   go run github.com/cilium/ebpf/cmd/bpf2go \
//     -target bpf Monitor bpf/monitoring.bpf.c -- -I/usr/include

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ─── Event type constants (must match monitor_linux.go) ──────────────────────
#define EVENT_PROCESS_CREATE  1
#define EVENT_PROCESS_EXIT    2
#define EVENT_FILE_WRITE      3
#define EVENT_FILE_DELETE     4
#define EVENT_NET_CONNECT     5
#define EVENT_FILE_OPEN       6   // file opened for read (suspicious reads)
#define EVENT_PTRACE          7   // ptrace attach (process injection on Linux)
#define EVENT_DNS_QUERY       8   // DNS query via sendto on port 53

// ─── Shared event structure ───────────────────────────────────────────────────
// Binary layout MUST match bpfEvent in monitor_linux.go exactly.
struct bpf_event {
    u64  timestamp;       // ktime_get_ns()
    u32  pid;             // PID of event source
    u32  ppid;            // parent PID
    u32  uid;             // UID (0 = root)
    u32  gid;             // GID
    char comm[16];        // short process name (task->comm)
    char filename[256];   // primary path/name
    u32  type;            // EVENT_* constant
    char target[256];     // secondary field (dest addr, new path, etc.)
    u32  flags;           // event-specific flags
    u32  dest_port;       // TCP/UDP destination port
    u32  src_port;        // TCP/UDP source port
    u8   dest_addr[16];   // IPv4 (4 bytes) or IPv6 (16 bytes)
    u8   src_addr[16];
    u8   addr_family;     // AF_INET=2, AF_INET6=10
    u8   _pad[3];
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

// Hash map: tracked PIDs → 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u8);
} target_pids SEC(".maps");

// Hash map: fd → filename for write enrichment (per-PID)
// Key: (pid << 32 | fd), Value: path[256]
struct fd_key { u32 pid; u32 fd; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_key);
    __type(value, char[256]);
} fd_path_map SEC(".maps");

// Ringbuffer for userland event delivery
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} events SEC(".maps");

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline bool is_monitored(u32 pid) {
    u8 *v = bpf_map_lookup_elem(&target_pids, &pid);
    return v != NULL;
}

static __always_inline void mark_monitored(u32 pid) {
    u8 one = 1;
    bpf_map_update_elem(&target_pids, &pid, &one, BPF_ANY);
}

static __always_inline void fill_common(struct bpf_event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->timestamp = bpf_ktime_get_ns();
    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid       = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ─── 1. sched_process_exec — new process execution ────────────────────────────
SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid  = bpf_get_current_pid_tgid() >> 32;
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    bool already = is_monitored(pid);
    bool parent_monitored = is_monitored(ppid);
    if (!already && !parent_monitored) return 0;

    mark_monitored(pid);

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_common(e);
    e->type = EVENT_PROCESS_CREATE;

    // Read executable path from bprm
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->bprm;
    if (bprm) {
        const char *fpath = BPF_CORE_READ(bprm, filename);
        if (fpath)
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), fpath);
    }

    // Read argv[0] as fallback comm into target field
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        if (arg_start)
            bpf_probe_read_user_str(e->target, sizeof(e->target),
                                   (const void *)arg_start);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── 2. sched_process_exit ────────────────────────────────────────────────────
SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_monitored(pid)) return 0;

    bpf_map_delete_elem(&target_pids, &pid);

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_common(e);
    e->type = EVENT_PROCESS_EXIT;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── 3. sys_enter_openat — capture fd→path for write enrichment ──────────────
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_monitored(pid)) return 0;

    const char *pathname = (const char *)ctx->args[1];
    if (!pathname) return 0;

    // We can't get the fd here (before the syscall returns), but we can
    // emit a file-open event for suspicious paths.
    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_common(e);
    e->type  = EVENT_FILE_OPEN;
    e->flags = (u32)ctx->args[2]; // flags (O_RDONLY=0, O_WRONLY=1, O_RDWR=2)

    bpf_probe_read_user_str(e->filename, sizeof(e->filename), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── 4. sys_enter_write — file write ─────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_write(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_monitored(pid)) return 0;

    unsigned int fd    = (unsigned int)ctx->args[0];
    size_t       count = (size_t)ctx->args[2];

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_common(e);
    e->type  = EVENT_FILE_WRITE;
    e->flags = fd;

    // Try to resolve path from fd_path_map (populated by openat exit hook)
    struct fd_key fk = { .pid = pid, .fd = fd };
    char *cached = bpf_map_lookup_elem(&fd_path_map, &fk);
    if (cached) {
        __builtin_memcpy(e->filename, cached, 256);
    } else {
        // Fallback: emit /proc/<pid>/fd/<fd> as a resolvable placeholder
        bpf_snprintf(e->filename, sizeof(e->filename),
                     "/proc/%u/fd/%u", pid, fd);
    }
    bpf_snprintf(e->target, sizeof(e->target), "bytes=%lu", count);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── 5. sys_enter_unlinkat — file deletion ────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_sys_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_monitored(pid)) return 0;

    const char *pathname = (const char *)ctx->args[1];

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_common(e);
    e->type = EVENT_FILE_DELETE;

    if (pathname)
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── 6. sys_enter_connect — outbound TCP/UDP ─────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_monitored(pid)) return 0;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) return 0;

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_common(e);
    e->type = EVENT_NET_CONNECT;

    sa_family_t family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family);
    e->addr_family = (u8)family;

    if (family == AF_INET) {
        struct sockaddr_in in4;
        bpf_probe_read_kernel(&in4, sizeof(in4), addr);
        e->dest_port = __builtin_bswap16(in4.sin_port);
        __builtin_memcpy(e->dest_addr, &in4.sin_addr.s_addr, 4);

        u32 ip = in4.sin_addr.s_addr;
        bpf_snprintf(e->filename, sizeof(e->filename), "%u.%u.%u.%u",
                     ip & 0xFF, (ip >> 8) & 0xFF,
                     (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
        bpf_snprintf(e->target, sizeof(e->target), "%u", e->dest_port);

        // DNS detection: port 53
        if (e->dest_port == 53)
            e->type = EVENT_DNS_QUERY;

    } else if (family == AF_INET6) {
        struct sockaddr_in6 in6;
        bpf_probe_read_kernel(&in6, sizeof(in6), addr);
        e->dest_port = __builtin_bswap16(in6.sin6_port);
        __builtin_memcpy(e->dest_addr, &in6.sin6_addr, 16);

        bpf_snprintf(e->target, sizeof(e->target), "[IPv6]:%u", e->dest_port);

        if (e->dest_port == 53)
            e->type = EVENT_DNS_QUERY;
    } else {
        bpf_snprintf(e->target, sizeof(e->target), "family=%u", (u32)family);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── 7. sys_enter_ptrace — Linux process injection detection ──────────────────
// ptrace(PTRACE_ATTACH, pid, ...) is the Linux equivalent of CreateRemoteThread
// and is used by tools like gdb-injection, process hollowing via ptrace, etc.
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_sys_ptrace(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_monitored(pid)) return 0;

    long request  = (long)ctx->args[0]; // PTRACE_ATTACH=16, PTRACE_POKETEXT=4
    u32  target   = (u32)ctx->args[1];  // target PID

    // Only report cross-process attach and write operations
    if (request != 16 /* PTRACE_ATTACH */ && request != 4 /* PTRACE_POKETEXT */ &&
        request != 31 /* PTRACE_SEIZE  */ && request != 25 /* PTRACE_PEEKDATA */) {
        return 0;
    }

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_common(e);
    e->type  = EVENT_PTRACE;
    e->flags = (u32)request;
    bpf_snprintf(e->filename, sizeof(e->filename), "ptrace_request=%ld", request);
    bpf_snprintf(e->target,   sizeof(e->target),   "target_pid=%u",  target);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
