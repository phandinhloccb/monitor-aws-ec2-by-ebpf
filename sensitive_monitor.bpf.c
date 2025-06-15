#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Constants for network address families
#define AF_INET     2
#define AF_INET6    10

// Event structure sent to userspace
// This must match the Go struct exactly for proper data transfer
struct event_t {
    u32 pid;            // Process ID
    u32 uid;            // Real UID (actual user)
    u32 euid;           // Effective User ID
    char comm[16];      // Process command name (truncated to 16 chars)
    char filename[256]; // File path being accessed
    char op[8];         // Operation type: "open", "exec", "conn", "send"
    u32 daddr;          // Destination IP address (network byte order)
    u16 dport;          // Destination port number
    u16 padding;        // Padding for struct alignment
};

// Perf event array map for sending events to userspace
// This creates a ring buffer for efficient data transfer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Per-CPU array map to store large event structures
// This avoids BPF stack limit issues (512 bytes max)
// Each CPU core gets its own copy to prevent race conditions
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} event_storage SEC(".maps");

// Helper function to check if an IP address should be filtered out
// Returns 1 if the IP should be ignored (local/AWS infrastructure)
static __always_inline int exclude_ip(u32 ip) {
    u32 ip_host = __builtin_bswap32(ip); // Convert to host byte order

    // AWS Instance Metadata Service (IMDS v1/v2)
    // Amazon Time Sync Service
    // Private VPC networks (10.0.0.0/8)
    if (ip_host == 0xA9FEA9FE)  return 1; // 169.254.169.254
    if (ip_host == 0xA9FEA97B)  return 1; // 169.254.169.123
    if ((ip_host & 0xFF000000) == 0x0A000000) return 1; // 10.x.x.x

    // AWS Tokyo region IP ranges (common ones)
    if ((ip_host & 0xFF000000) == 0x0D700000) return 1; // 13.112.0.0/14
    if ((ip_host & 0xFFFF0000) == 0x34C00000) return 1; // 52.192.0.0/15
    if ((ip_host & 0xFFFC0000) == 0x34C40000) return 1; // 52.196.0.0/14
    if ((ip_host & 0xFFF80000) == 0x36400000) return 1; // 54.64.0.0/13
    if ((ip_host & 0xFFFF8000) == 0x365C0000) return 1; // 54.92.0.0/17
    if ((ip_host & 0xFFFC0000) == 0x1F700000) return 1; // 3.112.0.0/14
    if ((ip_host & 0xFFFF0000) == 0x1F720000) return 1; // 3.114.0.0/16
    if ((ip_host & 0xFFFF0000) == 0x1F730000) return 1; // 3.115.0.0/16

    return 0; // External/suspicious IP
}

// Helper function to check if a file path is security-sensitive
// Returns 1 if the file should be monitored
static __always_inline int is_sensitive_file(const char *filename) {
    // List of critical system files that should trigger alerts
    const char *critical_files[] = {
        "/etc/ssh/sshd_config",                    // SSH daemon configuration
        "/etc/sudoers",                            // Sudo permissions
        "/etc/shadow",                             // Password hashes
        "/home/ec2-user/.ssh/authorized_keys",     // SSH public keys
        "/root/.ssh/authorized_keys",              // Root SSH keys
        "/var/log/auth.log",                       // Authentication logs
        "/var/log/secure",                         // Security logs (RHEL/CentOS)
        "/etc/crontab",                            // System cron jobs
        "/etc/systemd/system/",                    // Systemd service files
        "/opt/aws/amazon-cloudwatch-agent/",       // AWS CloudWatch agent
        "/opt/aws/awscli/"                         // AWS CLI configuration
    };

    // Check if filename matches any critical file pattern
    #pragma unroll
    for (int i = 0; i < 11; i++) {
        const char *target = critical_files[i];
        int len = __builtin_strlen(target);
        if (__builtin_memcmp(filename, target, len) == 0) {
            return 1; // Match found
        }
    }
    return 0; // Not a sensitive file
}

// Tracepoint handler for file open operations (openat syscall)
// Monitors access to sensitive configuration files
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // Get event storage from per-CPU map to avoid stack overflow
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0; // Map lookup failed
    
    // Initialize event structure to zero
    __builtin_memset(data, 0, sizeof(*data));
    
    // Extract filename from syscall arguments
    // openat(dirfd, pathname, flags, mode)
    const char *filename = (const char *)ctx->args[1];

    // Populate event data
    data->pid = bpf_get_current_pid_tgid() >> 32;  // Extract PID from combined value
    data->uid = bpf_get_current_uid_gid();         // Get current user ID
    bpf_get_current_comm(&data->comm, sizeof(data->comm)); // Get process name
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), filename); // Copy filename
    __builtin_memcpy(&data->op, "open", 5);       // Set operation type

    // Only send event if file is security-sensitive
    if (is_sensitive_file(data->filename)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    }
    return 0;
}

// Tracepoint handler for process execution (execve syscall)
// Monitors execution of security-related commands
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    // Get event storage from per-CPU map
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0;
    
    // Initialize event structure
    __builtin_memset(data, 0, sizeof(*data));
    
    // Extract program path from syscall arguments
    // execve(pathname, argv, envp)
    const char *filename = (const char *)ctx->args[0];

    // Get login UID (original user before privilege escalation)
    // This helps track sudo/su operations
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 loginuid = 0;
    bpf_core_read(&loginuid, sizeof(loginuid), &task->loginuid.val);

    // Trong populate event data:
    u64 uid_gid = bpf_get_current_uid_gid();
    data->uid = uid_gid & 0xFFFFFFFF;        // Real UID
    data->euid = uid_gid >> 32;              // Effective UID
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), filename);
    __builtin_memcpy(&data->op, "exec", 5);

    // Only monitor specific user management and privilege escalation commands
    if (__builtin_memcmp(data->filename, "/usr/sbin/useradd", 18) == 0 ||  // Add user
        __builtin_memcmp(data->filename, "/usr/sbin/usermod", 18) == 0 ||  // Modify user
        __builtin_memcmp(data->filename, "/usr/bin/passwd", 17) == 0 ||    // Change password
        __builtin_memcmp(data->filename, "/usr/sbin/userdel", 18) == 0 ||  // Delete user
        __builtin_memcmp(data->filename, "/usr/bin/su", 12) == 0 ||        // Switch user
        __builtin_memcmp(data->filename, "/usr/bin/sudo", 14) == 0) {      // Execute as another user
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    }
    return 0;
}

// Tracepoint handler for network connections (connect syscall)
// Monitors outbound network connections to detect data exfiltration
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    // Get event storage from per-CPU map
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0;
    
    // Initialize event structure
    __builtin_memset(data, 0, sizeof(*data));
    
    // Extract socket address from syscall arguments
    // connect(sockfd, addr, addrlen)
    struct sockaddr_in sa = {};
    struct sockaddr *user_sa = (struct sockaddr *)ctx->args[1];

    // Populate basic event data
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    __builtin_memcpy(&data->op, "conn", 5);

    // Read socket address from user space
    bpf_probe_read_user(&sa, sizeof(sa), user_sa);

    // Only process IPv4 connections
    if (sa.sin_family != AF_INET) {
        return 0;
    }

    data->daddr = sa.sin_addr.s_addr; // Store destination IP

    // Filter out local/AWS infrastructure traffic to reduce noise
    if (exclude_ip(sa.sin_addr.s_addr)) {
        return 0; // Skip local/expected connections
    }

    // Send event for suspicious external connections
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
}

// Tracepoint handler for network data transmission (sendto syscall)
// Monitors data being sent over the network
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    // Get event storage from per-CPU map
    u32 key = 0;
    struct event_t *data = bpf_map_lookup_elem(&event_storage, &key);
    if (!data)
        return 0;
    
    // Initialize event structure
    __builtin_memset(data, 0, sizeof(*data));
    
    // Extract arguments from syscall
    // sendto(sockfd, buf, len, flags, dest_addr, addrlen)
    int sockfd = (int)ctx->args[0];
    struct sockaddr *dest_addr = (struct sockaddr *)ctx->args[4];
    
    // Populate basic event data
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    __builtin_memcpy(&data->op, "send", 5);
    
    // Process destination address if provided
    if (dest_addr) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), dest_addr);
        
        // Only process IPv4 UDP/TCP traffic
        if (sa.sin_family == AF_INET && sa.sin_addr.s_addr != 0) {
            data->daddr = sa.sin_addr.s_addr;                    // Destination IP
            data->dport = __builtin_bswap16(sa.sin_port);        // Destination port (convert from network byte order)
            
            // Filter out local/expected traffic
            if (exclude_ip(sa.sin_addr.s_addr)) {
                return 0; // Skip local/AWS traffic
            }
            
            // Send event for suspicious external data transmission
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
        }
    }
    
    return 0;
}