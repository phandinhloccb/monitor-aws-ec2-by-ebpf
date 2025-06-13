#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define MAX_FILENAME_LEN 256

#define AF_INET     2
#define AF_INET6    10

struct event_t {
    u32 pid;        // 4 bytes
    u32 uid;        // 4 bytes  
    char comm[16];  // 16 bytes
    char filename[256]; // 256 bytes
    char op[8];     // 8 bytes
    u32 daddr;      // 4 bytes
    u16 dport;      // 2 bytes
    u16 padding;    // 2 bytes padding
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __always_inline int is_sensitive_file(const char *filename) {
    const char *critical_files[] = {
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/home/ec2-user/.ssh/authorized_keys",
        "/root/.ssh/authorized_keys",
        "/var/log/auth.log",
        "/var/log/secure",
        "/etc/crontab",
        "/etc/systemd/system/",
        "/opt/aws/amazon-cloudwatch-agent/",
        "/opt/aws/awscli/"
    };

    #pragma unroll
    for (int i = 0; i < 14; i++) {
        const char *target = critical_files[i];
        int len = __builtin_strlen(target);
        if (__builtin_memcmp(filename, target, len) == 0) {
            return 1;
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t data = {};
    const char *filename = (const char *)ctx->args[1];

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    __builtin_memcpy(&data.op, "open", 5);

    if (is_sensitive_file(data.filename)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t data = {};
    const char *filename = (const char *)ctx->args[0];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 loginuid = 0;
    bpf_core_read(&loginuid, sizeof(loginuid), &task->loginuid.val);

    data.uid = loginuid;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    __builtin_memcpy(&data.op, "exec", 5);

    if (__builtin_memcmp(data.filename, "/usr/sbin/useradd", 18) == 0 ||
        __builtin_memcmp(data.filename, "/usr/sbin/usermod", 18) == 0 ||
        __builtin_memcmp(data.filename, "/usr/bin/passwd", 17) == 0) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t data = {};
    struct sockaddr_in sa = {};
    struct sockaddr *user_sa = (struct sockaddr *)ctx->args[1];

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.op, "conn", 5);

    bpf_probe_read_user(&sa, sizeof(sa), user_sa);

    if (sa.sin_family != AF_INET) {
        return 0;
    }

    data.daddr = sa.sin_addr.s_addr;

    if (sa.sin_addr.s_addr == 0x7ba9fea9) { // 169.254.169.123
        return 0; // Skip AWS metadata traffic
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    struct event_t data = {};
    
    int sockfd = (int)ctx->args[0];
    struct sockaddr *dest_addr = (struct sockaddr *)ctx->args[4];
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.op, "send", 5);
    
    if (dest_addr) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), dest_addr);
        
        if (sa.sin_family == AF_INET && sa.sin_addr.s_addr != 0) {
            data.daddr = sa.sin_addr.s_addr;
            data.dport = __builtin_bswap16(sa.sin_port);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
        }
    }
    
    return 0;
}