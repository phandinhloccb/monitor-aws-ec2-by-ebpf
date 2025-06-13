### install golang with compile c and golang
```
sudo yum groupinstall "Development Tools" -y
sudo yum install clang llvm bpftool kernel-devel make -y
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c monitor_user_change.bpf.c -o monitor_user_change.bpf.o
go build -o monitor main.go
```