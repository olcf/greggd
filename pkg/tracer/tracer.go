package tracer

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/olcf/greggd/pkg/communication"
	"github.com/olcf/greggd/pkg/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

// Watch each configured memory map. Read perf events as they are sent.
// Otherwise output contents of memory maps as a poll
func pollOutputMaps(ctx context.Context, output config.BPFOutput,
	m *bcc.Module, dataChan chan config.SocketInput, errChan chan error,
	globals config.GlobalOptions, wg *sync.WaitGroup) {

	defer wg.Done()

	// Build output value data structure
	outputType, err := communication.BuildStructFromArray(output.Format)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error building output struct: %s\n", err)
		return
	}

	// Load in table to pass to individual watchers
	table := bcc.NewTable(m.TableId(output.Id), m)

	// Switch to individual watcher function based on hash type
	uppercaseType := strings.ToUpper(output.Type)
	if uppercaseType != "BPF_PERF_OUTPUT" && output.Poll == "" {
		errChan <- fmt.Errorf(
			"tracer.go: Watching non BPF_PERF_OUTPUT requires `poll` to be set")
		return
	}
	switch uppercaseType {
	case "BPF_PERF_OUTPUT":
		inputChan := make(chan []byte)
		defer close(inputChan)

		perfMap, err := bcc.InitPerfMap(table, inputChan)
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error building perf map: %s\n", err)
			return
		}
		perfMap.Start()
		// Set up listening on the output perf map channel. Needs to accept ctx
		// cancel
		readPerfChannel(ctx, outputType, inputChan, dataChan, errChan,
			&output, globals, output.Id)
		perfMap.Stop()
	case "BPF_HASH":
		// If hash, build output hash key data structure
		keyType, err := communication.BuildStructFromArray(
			[]config.BPFOutputFormat{output.Key})
		if err != nil {
			errChan <- fmt.Errorf(
				"tracer.go: Error building hash key type: %s\n", err)
			return
		}

		iterateHashMap(ctx, table, outputType, keyType.Field(0).Type, dataChan,
			errChan, &output, globals)
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
	dataChan chan config.SocketInput, errChan chan error,
	globals config.GlobalOptions, wg *sync.WaitGroup) {
	// Close waitgroup whenever we exit
	defer wg.Done()

	source, err := ioutil.ReadFile(program.Source)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Failed to read pgrogra source %s:%s\n",
			program.Source, err)
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
			errChan <- fmt.Errorf("tracer.go: Unable to attach to call %+v: %s\n",
				event, err)
			return
		}
	}

	// Load and watch output maps
	for _, output := range program.Outputs {
		wg.Add(1)
		go pollOutputMaps(ctx, output, m, dataChan, errChan, globals, wg)
	}
	wg.Wait()
}
