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

// Add per-cpu array map to store large event_t structures
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} event_storage SEC(".maps");

static __always_inline int is_aws_tokyo_ip(u32 ip) {
    u32 ip_host = __builtin_bswap32(ip);

    // Metadata Service (IMDS v1/v2)
    if (ip_host == 0xA9FEA9FE)  // 169.254.169.254
        return 1;

    // Amazon Time Sync Service
    if (ip_host == 0xA9FEA97B)  // 169.254.169.123
        return 1;

    // VPC nội bộ 10.0.0.0/8
    if ((ip_host & 0xFF000000) == 0x0A000000)  // 10.x.x.x
        return 1;


    // AWS Tokyo IP ranges
    if ((ip_host & 0xFF000000) == 0x0D700000) return 1; // 13.112.0.0/14
    if ((ip_host & 0xFFFF0000) == 0x34C00000) return 1; // 52.192.0.0/15
    if ((ip_host & 0xFFFC0000) == 0x34C40000) return 1; // 52.196.0.0/14
    if ((ip_host & 0xFFF80000) == 0x36400000) return 1; // 54.64.0.0/13
    if ((ip_host & 0xFFFF8000) == 0x365C0000) return 1; // 54.92.0.0/17
    if ((ip_host & 0xFFFC0000) == 0x1F700000) return 1; // 3.112.0.0/14
    if ((ip_host & 0xFFFF0000) == 0x1F720000) return 1; // 3.114.0.0/16
    if ((ip_host & 0xFFFF0000) == 0x1F730000) return 1; // 3.115.0.0/16
    if ((ip_host & 0xFFF80000) == 0x1F700000) return 1; // 3.112.0.0/13

    return 0;
}


static __always_inline int is_sensitive_file(const char *filename) {
    const char *critical_files[] = {
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/shadow",           // Chỉ giữ shadow, bỏ passwd vì quá nhiều noise
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
    for (int i = 0; i < 11; i++) {  // Giảm từ 14 xuống 11
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
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0;
    
    // Clear the structure
    __builtin_memset(data, 0, sizeof(*data));
    
    const char *filename = (const char *)ctx->args[1];

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), filename);
    __builtin_memcpy(&data->op, "open", 5);

    if (is_sensitive_file(data->filename)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    const char *filename = (const char *)ctx->args[0];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 loginuid = 0;
    bpf_core_read(&loginuid, sizeof(loginuid), &task->loginuid.val);

    data->uid = loginuid;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), filename);
    __builtin_memcpy(&data->op, "exec", 5);

    // Only monitor specific user management commands
    if (__builtin_memcmp(data->filename, "/usr/sbin/useradd", 18) == 0 ||
        __builtin_memcmp(data->filename, "/usr/sbin/usermod", 18) == 0 ||
        __builtin_memcmp(data->filename, "/usr/bin/passwd", 17) == 0 ||
        __builtin_memcmp(data->filename, "/usr/sbin/userdel", 18) == 0 ||
        __builtin_memcmp(data->filename, "/usr/bin/su", 12) == 0 ||
        __builtin_memcmp(data->filename, "/usr/bin/sudo", 14) == 0) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0;
    
    // Clear the structure
    __builtin_memset(data, 0, sizeof(*data));
    
    struct sockaddr_in sa = {};
    struct sockaddr *user_sa = (struct sockaddr *)ctx->args[1];

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    __builtin_memcpy(&data->op, "conn", 5);

    bpf_probe_read_user(&sa, sizeof(sa), user_sa);

    if (sa.sin_family != AF_INET) {
        return 0;
    }

    data->daddr = sa.sin_addr.s_addr;

    if (is_aws_tokyo_ip(sa.sin_addr.s_addr)) {
        return 0;
    }   

    // Only report suspicious external connections
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0;
    
    // Clear the structure
    __builtin_memset(data, 0, sizeof(*data));
    
    int sockfd = (int)ctx->args[0];
    struct sockaddr *dest_addr = (struct sockaddr *)ctx->args[4];
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    __builtin_memcpy(&data->op, "send", 5);
    
    if (dest_addr) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), dest_addr);
        
        if (sa.sin_family == AF_INET && sa.sin_addr.s_addr != 0) {
            data->daddr = sa.sin_addr.s_addr;
            data->dport = __builtin_bswap16(sa.sin_port);
            
            // Filter out local/expected traffic
            if (is_aws_tokyo_ip(sa.sin_addr.s_addr)) {
                return 0;
            }   
            
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
        }
    }
    
    return 0;
}