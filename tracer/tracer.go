package tracer

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/olcf/greggd/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

func pollOutputMaps(ctx context.Context, output config.BPFOutput,
	m *bcc.Module, errChan chan error) {

	table := bcc.NewTable(m.TableId(output.Id), m)
	dataChan := make(chan []byte)
	uppercaseType := strings.ToUpper(output.Type)
	switch uppercaseType {
	case "BPF_PERF_OUTPUT":
		perfMap, err := bcc.InitPerfMap(table, dataChan)
		if err != nil {
			errChan <- err
			return
		}
		perfMap.Start()
		for {
			select {
			case <-ctx.Done():
				fmt.Println("Done")
				break
			case inputBytes := <-dataChan:
				fmt.Println(inputBytes)
			}
		}
		perfMap.Stop()
	default:
		errChan <- fmt.Errorf("tracer.go: Output type %s is not supported",
			output.Type)
	}
}

func attachAndLoadEvent(event config.BPFEvent, m *bcc.Module) error {
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
	errChan chan error, wg *sync.WaitGroup) {
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

	// Load and watch  output maps
	for _, output := range program.Outputs {
		go pollOutputMaps(ctx, output, m, errChan)
	}
}
