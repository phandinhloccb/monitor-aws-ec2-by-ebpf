package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
	Op       [8]byte
	Daddr    uint32
	Dport    uint16
	_        [2]byte // padding cho align (do struct alignment)
}

func formatIPv4(addr uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}

func main() {
	log.Println("🔍 Starting Sensitive Monitor (open/exec/send/conn)...")

	spec, err := ebpf.LoadCollectionSpec("sensitive_monitor.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	var objs struct {
		Programs struct {
			TraceOpenat  *ebpf.Program `ebpf:"trace_openat"`
			TraceExecve  *ebpf.Program `ebpf:"trace_execve"`
			TraceSendto  *ebpf.Program `ebpf:"trace_sendto"`
			TraceConnect *ebpf.Program `ebpf:"trace_connect"`
		}
		Maps struct {
			Events *ebpf.Map `ebpf:"events"`
		}
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign: %v", err)
	}
	defer objs.Programs.TraceOpenat.Close()
	defer objs.Programs.TraceExecve.Close()
	defer objs.Programs.TraceSendto.Close()
	defer objs.Programs.TraceConnect.Close()
	defer objs.Maps.Events.Close()

	// Attach tracepoints
	links := []struct {
		tpCategory string
		tpName     string
		prog       *ebpf.Program
	}{
		{"syscalls", "sys_enter_openat", objs.Programs.TraceOpenat},
		{"syscalls", "sys_enter_execve", objs.Programs.TraceExecve},
		{"syscalls", "sys_enter_sendto", objs.Programs.TraceSendto},
		{"syscalls", "sys_enter_connect", objs.Programs.TraceConnect},
	}

	for _, l := range links {
		tp, err := link.Tracepoint(l.tpCategory, l.tpName, l.prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach %s/%s: %v", l.tpCategory, l.tpName, err)
		}
		defer tp.Close()
	}

	log.Println("✅ eBPF programs attached!")

	rd, err := perf.NewReader(objs.Maps.Events, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				log.Printf("Perf event read error: %v", err)
				continue
			}

			var e event
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e)
			if err != nil {
				log.Printf("Failed to decode event: %v", err)
				continue
			}

			op := string(bytes.Trim(e.Op[:], "\x00"))
			comm := string(bytes.Trim(e.Comm[:], "\x00"))

			switch op {
			case "open", "exec":
				filename := string(bytes.Trim(e.Filename[:], "\x00"))
				fmt.Printf("🔍 PID=%d UID=%d COMM=%s OP=%s FILE=%s\n",
					e.Pid, e.Uid, comm, op, filename)
			case "send", "conn", "sendto": // ← Thêm "sendto"
				ip := formatIPv4(e.Daddr)
				fmt.Printf("🌐 PID=%d UID=%d COMM=%s OP=%s DST=%s:%d\n",
					e.Pid, e.Uid, comm, op, ip, e.Dport)
			default:
				filename := string(bytes.Trim(e.Filename[:], "\x00"))
				fmt.Printf("❓ Unknown op: %s, PID=%d UID=%d COMM=%s FILE=%s\n",
					op, e.Pid, e.Uid, comm, filename)
			}
		}
	}()

	<-sig
	log.Println("⏹ Exiting")
}
