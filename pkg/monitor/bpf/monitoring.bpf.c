#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Type definitions matching monitor_linux.go
#define EVENT_TYPE_PROCESS_CREATE 1
#define EVENT_TYPE_PROCESS_EXIT   2
#define EVENT_TYPE_FILE_WRITE     3
#define EVENT_TYPE_FILE_DELETE    4
#define EVENT_TYPE_NET_CONNECT    5

struct bpf_event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
    u32 type;
    char target[256];
};

// Map tracking PIDs belonging to the sandbox tree
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u8);
} target_pids SEC(".maps");

// Ringbuffer to stream events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB ringbuf
} events SEC(".maps");

// Helper to check if a PID is monitored
static __always_inline bool is_monitored(u32 pid) {
    u8 *monitored = bpf_map_lookup_elem(&target_pids, &pid);
    return monitored != NULL;
}

// 1. Process creation tracepoint
SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Check if parent or current process is monitored
    bool monitor_this = is_monitored(ppid) || is_monitored(pid);

    if (!monitor_this) {
        return 0;
    }

    // Auto-propagate tracking to the child process
    u8 active = 1;
    bpf_map_update_elem(&target_pids, &pid, &active, BPF_ANY);

    // Reserve space in ringbuf
    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->ppid = ppid;
    e->uid = uid;
    e->type = EVENT_TYPE_PROCESS_CREATE;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Read binary path of the executed program
    struct linux_binprm *bprm = (struct linux_binprm *)BPF_CORE_READ(ctx, bprm);
    const char *filename_ptr = BPF_CORE_READ(bprm, filename);
    if (filename_ptr) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 2. Process exit tracepoint
SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_monitored(pid)) {
        return 0;
    }

    // Clean up tracking map entry
    bpf_map_delete_elem(&target_pids, &pid);

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->type = EVENT_TYPE_PROCESS_EXIT;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 3. Syscall write hook (to track file write modifications)
SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_write(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_monitored(pid)) {
        return 0;
    }

    unsigned int fd = (unsigned int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    // Read target file path from process FD table (reference path parsing helper)
    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->type = EVENT_TYPE_FILE_WRITE;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Simplification for tracepoint: report fd and size in filename/target fields
    bpf_snprintf(e->filename, sizeof(e->filename), "/proc/self/fd/%d", fd);
    bpf_snprintf(e->target, sizeof(e->target), "bytes_written=%lu", count);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 4. Syscall unlinkat hook (file deletion)
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_sys_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_monitored(pid)) {
        return 0;
    }

    const char *pathname = (const char *)ctx->args[1];

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->type = EVENT_TYPE_FILE_DELETE;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    if (pathname) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), pathname);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 5. Syscall connect hook (outbound network connections)
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_monitored(pid)) {
        return 0;
    }

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) return 0;

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->type = EVENT_TYPE_NET_CONNECT;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read family
    sa_family_t family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in in_addr;
        bpf_probe_read_kernel(&in_addr, sizeof(in_addr), addr);
        
        u32 ipv4 = in_addr.sin_addr.s_addr;
        u16 port = __builtin_bswap16(in_addr.sin_port);

        bpf_snprintf(e->target, sizeof(e->target), "%d.%d.%d.%d:%d",
                     (ipv4) & 0xFF, (ipv4 >> 8) & 0xFF,
                     (ipv4 >> 16) & 0xFF, (ipv4 >> 24) & 0xFF, port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 in_addr6;
        bpf_probe_read_kernel(&in_addr6, sizeof(in_addr6), addr);
        u16 port = __builtin_bswap16(in_addr6.sin6_port);
        
        bpf_snprintf(e->target, sizeof(e->target), "[IPv6]:%d", port);
    } else {
        bpf_snprintf(e->target, sizeof(e->target), "family=%d", family);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
