clang -O2 -g -target bpf -c sensitive_monitor.bpf.c -o sensitive_monitor.bpf.o
go build -o monitor main.go
sudo ./monitor