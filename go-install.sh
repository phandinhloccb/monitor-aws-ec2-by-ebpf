# Install go
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version

# Install bpftool and kernel-devel
sudo yum groupinstall "Development Tools" -y
sudo yum install clang llvm bpftool kernel-devel make -y
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h