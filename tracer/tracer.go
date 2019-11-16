package tracer

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"github.com/olcf/greggd/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

// Watch each configured memory map. Read perf events as they are sent.
// Otherwise output contents of memory maps as a poll
func pollOutputMaps(ctx context.Context, output config.BPFOutput,
	m *bcc.Module, errChan chan error, c net.Conn, mux *sync.Mutex,
	wg *sync.WaitGroup) {

	defer wg.Done()

	// Build output data structure
	outputType, err := buildStructFromArray(output.Format)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error building output struct: %s\n", err)
		return
	}

	dataChan := make(chan []byte, 1000)
	uppercaseType := strings.ToUpper(output.Type)
	switch uppercaseType {
	case "BPF_PERF_OUTPUT":
		table := bcc.NewTable(m.TableId(output.Id), m)
		perfMap, err := bcc.InitPerfMap(table, dataChan)
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error building perf map: %s\n", err)
			return
		}
		perfMap.Start()
		// Set up listening on the output perf map channel. Needs to accept ctx
		// cancel
		readPerfChannel(ctx, outputTupe, dataChan, errChan, c, mux)
		perfMap.Stop()
	case "BPF_HASH":
	case "BPF_HISTOGRAM":
	default:
		errChan <- fmt.Errorf("tracer.go: Output type %s is not supported",
			output.Type)
	}
}

func attachAndLoadEvent(event config.BPFEvent, m *bcc.Module) error {
	if event.AttachTo == "" || event.Type == "" {
		return fmt.Errorf("tracer.go: Event has missing keys")
	}
	lowercaseType := strings.ToLower(event.Type)
	switch lowercaseType {
	case "kprobe":
		fd, err := m.LoadKprobe(event.LoadFunc)
		if err != nil {
			return err
		}

		err = m.AttachKprobe(event.AttachTo, fd)
		if err != nil {
			return err
		}
	case "kretprobe":
		fd, err := m.LoadKprobe(event.LoadFunc)
		if err != nil {
			return err
		}

		err = m.AttachKretprobe(event.AttachTo, fd)
		if err != nil {
			return err
		}
	case "rawtracepoint":
		fd, err := m.LoadRawTracepoint(event.LoadFunc)
		if err != nil {
			return err
		}

		err = m.AttachRawTracepoint(event.AttachTo, fd)
		if err != nil {
			return err
		}
	case "tracepoint":
		fd, err := m.LoadTracepoint(event.LoadFunc)
		if err != nil {
			return err
		}

		err = m.AttachTracepoint(event.AttachTo, fd)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("tracer.go: Program type %s is not supported",
			event.Type)
	}

	return nil
}

func Trace(ctx context.Context, program config.BPFProgram,
	errChan chan error, sockAddr string, mux *sync.Mutex, wg *sync.WaitGroup) {
	// Close waitgroup whenever we exit
	defer wg.Done()

	source, err := ioutil.ReadFile(program.Source)
	if err != nil {
		fmt.Errorf("\ntracer.go: Failed to read %s:\n%s", program.Source, err)
	}

	// Compile a bpf module, load it into the kernel. Pass empty c flags to bcc
	// during compilation
	m := bcc.NewModule(string(source), []string{})
	// Close all probes and unload the ebpf module from the kernel
	defer m.Close()

	// Attach events to kernel calls
	for _, event := range program.Events {
		err = attachAndLoadEvent(event, m)
		if err != nil {
			errChan <- err
			return
		}
	}

	// Open Socket
	c, err := net.Dial("unix", sockAddr)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error dialing socket %s: %s\n",
			sockAddr, err)
		return
	}

	// Load and watch  output maps
	for _, output := range program.Outputs {
		wg.Add(1)
		go pollOutputMaps(ctx, output, m, errChan, c, mux, wg)
	}
	wg.Wait()
}
