package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Event structure that matches the BPF C struct
// This must be kept in sync with the BPF code
type event struct {
	Pid      uint32    // Process ID
	Uid      uint32    // Real UID (actual user)
	Euid     uint32    // Effective UID (current privileges)
	Comm     [16]byte  // Command name (process name)
	Filename [256]byte // File path being accessed
	Op       [8]byte   // Operation type (open, exec, conn, send)
	Daddr    uint32    // Destination IP address (for network operations)
	Dport    uint16    // Destination port (for network operations)
	_        [2]byte   // Padding for struct alignment
}

// getUsername resolves UID to username using system lookup
// Falls back to static mapping for common system users
func getUsername(uid uint32) string {
	// Try dynamic system lookup first - this will find any user in /etc/passwd
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		return u.Username
	}

	// Fallback to static mapping for common system users
	// This is used when system lookup fails
	switch uid {
	case 0:
		return "root"
	case 1000:
		return "ec2-user" // Default AWS EC2 user
	default:
		return fmt.Sprintf("uid-%d", uid) // Unknown user, show as uid-XXXX
	}
}

// formatIPv4 converts a uint32 IP address to dotted decimal notation
func formatIPv4(addr uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}

// shouldSkipProcess filters out noisy system processes to reduce log spam
func shouldSkipProcess(comm string) bool {
	skipList := []string{
		"systemd-userwor", // systemd user worker processes
		"chronyd",         // NTP daemon
		"amazon-ssm-agen", // AWS Systems Manager agent
		"ps",              // Process status command (very noisy)
	}

	for _, skip := range skipList {
		if comm == skip {
			return true
		}
	}
	return false
}

func main() {
	log.Println("🔍 Starting Sensitive Monitor (open/exec/send/conn)...")

	// Load the compiled BPF object file
	spec, err := ebpf.LoadCollectionSpec("sensitive_monitor.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	// Define the BPF objects structure
	// This must match the program and map names in the BPF C code
	var objs struct {
		Programs struct {
			TraceOpenat  *ebpf.Program `ebpf:"trace_openat"`  // File open monitoring
			TraceExecve  *ebpf.Program `ebpf:"trace_execve"`  // Process execution monitoring
			TraceSendto  *ebpf.Program `ebpf:"trace_sendto"`  // Network send monitoring
			TraceConnect *ebpf.Program `ebpf:"trace_connect"` // Network connection monitoring
		}
		Maps struct {
			Events *ebpf.Map `ebpf:"events"` // Perf event array for data transfer
		}
	}

	// Load BPF programs and maps into kernel
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign: %v", err)
	}

	// Ensure cleanup on exit
	defer objs.Programs.TraceOpenat.Close()
	defer objs.Programs.TraceExecve.Close()
	defer objs.Programs.TraceSendto.Close()
	defer objs.Programs.TraceConnect.Close()
	defer objs.Maps.Events.Close()

	// Define tracepoints to attach BPF programs to
	// Each tracepoint corresponds to a system call entry point
	links := []struct {
		tpCategory string        // Tracepoint category
		tpName     string        // Tracepoint name
		prog       *ebpf.Program // BPF program to attach
	}{
		{"syscalls", "sys_enter_openat", objs.Programs.TraceOpenat},   // File open syscall
		{"syscalls", "sys_enter_execve", objs.Programs.TraceExecve},   // Process exec syscall
		{"syscalls", "sys_enter_sendto", objs.Programs.TraceSendto},   // Network send syscall
		{"syscalls", "sys_enter_connect", objs.Programs.TraceConnect}, // Network connect syscall
	}

	// Attach BPF programs to kernel tracepoints
	for _, l := range links {
		tp, err := link.Tracepoint(l.tpCategory, l.tpName, l.prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach %s/%s: %v", l.tpCategory, l.tpName, err)
		}
		defer tp.Close() // Ensure detachment on exit
	}

	log.Println("✅ eBPF programs attached!")

	// Create perf event reader to receive data from BPF programs
	rd, err := perf.NewReader(objs.Maps.Events, 4096) // 4KB buffer
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	// Setup signal handling for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Start event processing goroutine
	go func() {
		for {
			// Read event from BPF program
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return // Reader closed, exit goroutine
				}
				log.Printf("Perf event read error: %v", err)
				continue
			}

			// Decode binary event data into Go struct
			var e event
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e)
			if err != nil {
				log.Printf("Failed to decode event: %v", err)
				continue
			}

			// Extract string fields from byte arrays (remove null terminators)
			op := string(bytes.Trim(e.Op[:], "\x00"))     // Operation type
			comm := string(bytes.Trim(e.Comm[:], "\x00")) // Process name

			// Filter out noisy system processes
			if shouldSkipProcess(comm) {
				continue
			}

			// Process different types of security events
			switch op {
			case "open", "exec":
				// File access and process execution events
				filename := string(bytes.Trim(e.Filename[:], "\x00"))
				username := getUsername(e.Uid)
				effective_username := getUsername(e.Euid)

				if e.Uid != e.Euid {
					// Show privilege escalation
					fmt.Printf("🚨 SENSITIVE: PID=%d UID=%d(%s)→%d(%s) COMM=%s OP=%s FILE=%s\n",
						e.Pid, e.Uid, username, e.Euid, effective_username, comm, op, filename)
				} else {
					// Normal operation
					fmt.Printf("🚨 SENSITIVE: PID=%d UID=%d USER=%s COMM=%s OP=%s FILE=%s\n",
						e.Pid, e.Uid, username, comm, op, filename)
				}

			case "send", "conn", "sendto":
				// Network activity events
				ip := formatIPv4(e.Daddr)
				fmt.Printf("🌐 EXTERNAL: PID=%d UID=%d USER=%s COMM=%s OP=%s DST=%s:%d\n",
					e.Pid, e.Uid, getUsername(e.Uid), comm, op, ip, e.Dport)

			default:
				// Unknown operation type
				filename := string(bytes.Trim(e.Filename[:], "\x00"))
				fmt.Printf("❓ Unknown op: %s, PID=%d UID=%d USER=%s COMM=%s FILE=%s\n",
					op, e.Pid, e.Uid, getUsername(e.Uid), comm, filename)
			}
		}
	}()

	// Wait for shutdown signal
	<-sig
	log.Println("⏹ Exiting")
}
