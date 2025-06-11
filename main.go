package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "strings"
    "time"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/cloudwatchlogs"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

type event struct {
    PID      uint32
    Comm     [16]byte
    Filename [256]byte
}

const logGroup = "ebpf-user-monitor"
const logStream = "execve-events"

func main() {
    log.Println("Starting eBPF program...")
    spec, err := ebpf.LoadCollectionSpec("monitor_user_change.bpf.o")
    if err != nil {
        log.Fatalf("Failed to load eBPF program: %v", err)
    }

    objs := struct {
        Program *ebpf.Program `ebpf:"trace_execve"`
        Events  *ebpf.Map     `ebpf:"event"`
    }{}

    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        log.Fatalf("Failed to load and assign eBPF objects: %v", err)
    }

    defer objs.Program.Close()
    defer objs.Events.Close()

    tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.Program, nil)
    if err != nil {
        log.Fatalf("Failed to attach tracepoint: %v", err)
    }
    defer tp.Close()

    log.Println("Tracepoint attached successfully")

    reader, err := perf.NewReader(objs.Events, os.Getpagesize())
    if err != nil {
        log.Fatalf("Failed to create perf reader: %v", err)
    }
    defer reader.Close()

    sess := session.Must(session.NewSession(&aws.Config{
        Region: aws.String("ap-northeast-1"),
    }))
    svc := cloudwatchlogs.New(sess)

    ensureLogGroupAndStream(svc)
    sequenceToken := ""

    for {
        record, err := reader.Read()
        if err != nil {
            log.Printf("Error reading from perf buffer: %v", err)
            continue
        }

        var e event
        if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
            log.Printf("Parsing event: %v", err)
            continue
        }

        msg := fmt.Sprintf(
            "PID=%d COMM=%s FILE=%s",
            e.PID,
            bytesToString(e.Comm[:]),
            bytesToString(e.Filename[:]),
        )
        log.Println(msg)

        input := &cloudwatchlogs.PutLogEventsInput{
            LogEvents: []*cloudwatchlogs.InputLogEvent{
                {
                    Message:   aws.String(msg),
                    Timestamp: aws.Int64(time.Now().Unix() * 1000),
                },
            },
            LogGroupName:  aws.String(logGroup),
            LogStreamName: aws.String(logStream),
        }

        if sequenceToken != "" {
            input.SequenceToken = aws.String(sequenceToken)
        }

        out, err := svc.PutLogEvents(input)
        if err != nil {
            log.Printf("PutLogEvents error: %v", err)
            continue
        }

        if out != nil && out.NextSequenceToken != nil {
            sequenceToken = *out.NextSequenceToken
        }
    }
}

func ensureLogGroupAndStream(svc *cloudwatchlogs.CloudWatchLogs) {
    _, _ = svc.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
        LogGroupName: aws.String(logGroup),
    })

    _, _ = svc.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
        LogGroupName:  aws.String(logGroup),
        LogStreamName: aws.String(logStream),
    })
}

func bytesToString(b []byte) string {
    return strings.TrimRight(string(b), "\x00")
}