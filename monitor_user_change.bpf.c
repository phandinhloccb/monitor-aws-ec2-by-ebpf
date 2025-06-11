#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define MAX_FILENAME_LEN 256

struct event_t {
    u32 pid;
    char comm[16];
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} event SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t data = {};
    const char *filename = (const char *)ctx->args[0];

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    if (__builtin_memcmp(data.filename, "/usr/sbin/useradd", 18) == 0 ||
        __builtin_memcmp(data.filename, "/usr/sbin/usermod", 18) == 0 ||
        __builtin_memcmp(data.filename, "/usr/bin/passwd", 17) == 0) {
        bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}