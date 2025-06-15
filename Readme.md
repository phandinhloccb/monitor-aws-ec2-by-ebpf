# 🛡️ Deep Kernel Monitoring with eBPF on AWS EC2

## 👋 Giới thiệu

Amazon CloudWatch Agent giúc bạn thu thập metrics và logs cơ bản từ hệ thống EC2 như CPU, memory, disk hoặc log file. Tuy nhiên, bạn sẽ **không thể nào giám sát được các hành vi nhạy cảm trong kernel** – chẳng hạn như:

- Một tiến trình cố truy cập file `/etc/shadow`?
- Một container gửi dữ liệu ra ngoài đến một IP lạ?
- Một lệnh `usermod` được chạy bởi tiến trình `sudo`?

Những sự kiện đó không có trong CloudWatch logs. Vậy giải pháp là gì?

## 🔬 Tôi đã học được gì từ eBPF?

Tôi đã triển khai một chương trình eBPF để **giám sát kernel trực tiếp trên AWS EC2**. Bài viết này chia sẻ lại kết quả và cách tôi tối ưu để không bị "ngợp" trong dữ liệu.

---

## 📌 Mục tiêu

- **Quan sát các hoạt động nhạy cảm trong kernel mà CloudWatch Agent không hỗ trợ.**
- Tối ưu để **chỉ nhận dữ liệu “quan trọng”, giảm noise và tăng hiệu quả.**
- Dễ tích hợp với hệ thống alert hoặc logging như CloudWatch Logs, OpenSearch, hoặc SIEM.

---

## 🧠 Kiến trúc tổng quan

```text
[eBPF Program (C)] --> [Perf Buffer] --> [Go Agent] --> [Console or CloudWatch Logs]
```

- eBPF program được viết bằng C và attach vào các `syscalls`: `openat`, `execve`, `connect`, `sendto`.
- Dữ liệu được chuyển lên user-space qua perf event buffer.
- Go Agent sẽ đọc buffer này và in ra hoặc gửi đi nơi khác.

---

## 🔍 Những gì tôi giám sát

### 1. **Mở file quan trọng**

Trace `openat()` và lọc theo các file nhạy cảm:

```c
const char *critical_files[] = {
    "/etc/shadow",
    "/etc/sudoers",
    "/home/ec2-user/.ssh/authorized_keys",
    ...
};
```

→ Bất kỳ truy cập nào vào các file trên sẽ tạo alert.

### 2. **Lệnh nguy hiểm**

Trace `execve()` và chỉ lọc:

- `/usr/sbin/useradd`
- `/usr/bin/passwd`
- `/usr/bin/sudo`
- `/usr/bin/su`

→ Giúp tôi phát hiện hành vi thao tác user/group.

### 3. **Kết nối ra ngoài**

Trace `connect()` và `sendto()`:

- Lọc theo địa chỉ IP bên ngoài (không phải AWS internal).
- Loại trừ các IP thường gặp trong AWS như:
  - `169.254.169.254` (Instance Metadata Service)
  - `10.0.0.0/8`
  - Một số dải IP Tokyo như `13.112.0.0/14`, `3.114.0.0/16`, v.v.

```c
if (exclude_ip(ip)) return 0;
```

→ Chỉ báo cáo các connection **đáng nghi ra bên ngoài**.

---

## 🧪 Output minh họệ

Ví dụ output từ Go Agent:

```bash
🚨 SENSITIVE: PID=18293 UID=1007 USER=ebpfuser COMM=bash OP=exec FILE=/usr/bin/sudo
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers.d
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers.d
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers.d/90-cloud-init-users
🚨 SENSITIVE: PID=18294 UID=0 USER=root COMM=unix_chkpwd OP=open FILE=/etc/shadow
🌐 EXTERNAL: PID=18296 UID=0 USER=root COMM=curl OP=conn DST=172.217.161.46:0
🌐 EXTERNAL: PID=18296 UID=0 USER=root COMM=curl OP=conn DST=172.217.161.46:0
```

→ Rất dễ tích hợp với Promtail, Fluent Bit hoặc gửi thẳng lên CloudWatch Logs để làm dashboard hoặc tạo alarm.

---

## 🔧 Tối ưu hóa

### ✅ Dùng `exclude_ip()`

Giảm bớt noise từ metadata service, IP AWS nội bộ.

### ✅ Dùng `is_sensitive_file()`

Tránh gửi event cho mọi file – chỉ gửi khi thực sự nhạy cảm.

### ✅ Dùng `BPF_MAP_TYPE_PERCPU_ARRAY`

Giảm stack pressure bằng cách dùng map để lưu struct lớn `event_t`.

---

## 🔒 Lý do vì sao CloudWatch chưa đủ

| Hành vi                           | CloudWatch Agent | eBPF |
| --------------------------------- | ---------------- | ---- |
| Truy cập file nhạy cảm            | ❌                | ✅    |
| Gọi lệnh useradd/passwd/sudo      | ❌                | ✅    |
| Kết nối đến IP bên ngoài đáng ngờ | ❌                | ✅    |
| Gửi dữ liệu đến IP lạ             | ❌                | ✅    |

CloudWatch chỉ lấy được syslog hoặc log file – nhưng nếu một tiến trình "không log", bạn sẽ không biết nó đã làm gì.

---

## 📌 Code mẫu

### eBPF C (rút gọn):

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(...) {
    ...
    if (__builtin_memcmp(data->filename, "/usr/bin/passwd", 17) == 0) {
        bpf_perf_event_output(...);
    }
    ...
}
```

### Go agent:

```go
for {
    record, err := reader.Read()
    var e Event
    binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e)
    fmt.Printf("[ALERT] %s | uid=%d pid=%d comm=%q filename=%q\n",
        e.Op, e.UID, e.PID, e.Comm, e.Filename)
}
```

## 📈 Tiếp theo

- Gửi event lên CloudWatch Logs bằng AWS SDK Go.
- Gắn tag EC2 (tên app, env, v.v.) để phân tích.
- Export ra OpenSearch làm SIEM dashboard.
- Dùng Lambda xử lý log để cảnh báo real-time.

---

## 🆚 So sánh với các phương pháp khác

| Giải pháp         | Ưu điểm                                                                                                             | Hạn chế                                                                                               |
| ----------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **eBPF**          | - Realtime, chạy trong kernel- Được verifier kiểm tra an toàn- Không cần thay đổi kernel- Linh hoạt, tùy chỉnh code | - Cần hiểu sâu về kernel- Chưa phổ biến rộng rãi                                                      |
| **Kernel Module** | - Toàn quyền, quyền lực tuyệt đối- Dễ can thiệp sâu                                                                 | - Rủi ro cao (crash kernel)- Không được verifier kiểm tra lỗi- Không tương thích giữa kernel versions |
| **Datadog Agent** | - Dễ dùng, có dashboard- Tích hợp log/metrics sẵn                                                                   | - Cần gửi log ra ngoài- Không giám sát được hành vi kernel-level sâu                                  |

**eBPF là một điểm cân bằng tuyệt vời**:

- Vừa **an toàn** hơn so với Kernel Module nhờ eBPF Verifier kiểm tra lỗi.
- Vừa **riêng tư & realtime**, không cần gửi toàn bộ log ra bên ngoài như Datadog.

---

## 🔐 Vì sao eBPF được xem là “an toàn”?

Một trong những lý do eBPF trở nên nổi bật so với việc viết Kernel Module là vì **mỗi chương trình eBPF phải đi qua một bộ kiểm tra chặt chẽ gọi là Verifier** trước khi được nạp vào kernel.

### 📎 eBPF Verifier là gì?

Verifier là một cơ chế trong kernel dùng để:

- **Phân tích toàn bộ code eBPF** trước khi nó được phép chạy.
- Kiểm tra các điều kiện:
  - Không có vòng lặp vô tận.
  - Tránh truy cập bộ nhớ ngoài phạm vi cho phép.
  - Kiểm tra logic đường đi của chương trình (control flow).
  - Không sử dụng con trỏ sai cách hoặc syscalls bị cấm.

### 🧪 Ví dụ trong chương trình của tôi

Trong đoạn code sau, tôi lọc `execve()` chỉ với một lệnh cụ thể:

```c
if (__builtin_memcmp(data->filename, "/usr/bin/passwd", 17) == 0) {
    bpf_perf_event_output(...);
}
```

Nếu tôi viết sai (ví dụ truy cập vùng nhớ chưa khởi tạo, hoặc deref con trỏ NULL), **verifier sẽ từ chối chương trình và báo lỗi ngay lập tức**, chứ không để nó gây crash kernel như module truyền thống.

### 📎 eBPF Verifier là gì?

Verifier là một cơ chế trong kernel dùng để:

- **Phân tích toàn bộ bytecode eBPF** trước khi nó được phép chạy.
- Kiểm tra các điều kiện:
  - Không có vòng lặp vô tận.
  - Tránh truy cập bộ nhớ ngoài phạm vi cho phép.
  - Kiểm tra logic đường đi của chương trình (control flow).
  - Không sử dụng con trỏ sai cách hoặc syscalls bị cấm.

Verifier sẽ **từ chối chương trình ngay khi bạn cố tải nó vào kernel** nếu phát hiện lỗi như truy cập vùng nhớ chưa được cấp phát, con trỏ NULL, vòng lặp vô hạn hoặc thao tác nguy hiểm.

Điều này dựa trên thiết kế đặc biệt của eBPF — chương trình eBPF chạy dưới dạng bytecode được kernel phân tích kỹ lưỡng trước khi thực thi, chứ không phải code máy chạy trực tiếp như kernel module. Verifier là thành phần đảm bảo tính an toàn và ổn định cho kernel khi chạy eBPF.


### ✅ Ưu điểm rõ ràng từ verifier

| Tính năng                              | Kernel Module ❌ | eBPF ✅                |
| -------------------------------------- | --------------- | --------------------- |
| Được kiểm tra static trước khi chạy    | ❌               | ✅                     |
| Ngăn truy cập bộ nhớ nguy hiểm         | ❌               | ✅                     |
| Bảo vệ chống crash toàn bộ hệ thống    | ❌               | ✅                     |
| Cho phép người không phải root sử dụng | ❌               | ✅ (nếu cấu hình đúng) |

---

### 💥 Vì sao viết Kernel Module dễ gây crash?

Kernel Module là cách "cổ điển" để thêm tính năng vào Linux kernel. Tuy nhiên, **nó chạy với toàn quyền trong không gian kernel**, nên chỉ cần một lỗi nhỏ là có thể khiến toàn bộ hệ thống sập.

#### ❌ Ví dụ cụ thể:

Một đoạn code sai trong Kernel Module có thể gây crash toàn bộ hệ thống:

```c
char *ptr = NULL;
printk(KERN_INFO "Data: %s\n", ptr);  // dereference NULL pointer
```

→ Khi module này được nạp, kernel sẽ panic vì dereference con trỏ `NULL`.

#### 🆚 So sánh với eBPF

Nếu bạn viết code eBPF tương tự:

```c
char *ptr = NULL;
bpf_trace_printk("Data: %s\n", ptr);  // unsafe
```

→ **Verifier sẽ từ chối chương trình này ngay khi bạn cố **``** nó vào kernel**. Không có cơ hội gây crash.

---

---

## 🎯 Kết luận

Việc triển khai eBPF để quan sát EC2 đã giúc tôi:

- **Phát hiện các hành vi kernel-level mà không cần agent bên ngoài.**
- **Giảm false-positive nhờ filter thông minh.**
- **Hiểu rõ hơn về hoạt động thật sự của hệ thống.**

eBPF không còn là “black magic” nữa. Nó là công cụ mạnh mẻ, cực kỳ hiệu quả khi bạn biết **filter đúng thứ bạn cần.**

---

## 📒 Tài liệu tham khảo

- [eBPF Official](https://ebpf.io/)
- [bcc-tools](https://github.com/iovisor/bcc)
- [Cilium eBPF Examples](https://github.com/cilium/ebpf)
- [AWS CloudWatch Agent](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html)

