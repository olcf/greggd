package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/olcf/greggd/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

func pollOutputMaps(ctx context.Context, output config.BPFOutput,
	m *bcc.Module, errChan chan error) {

	// Build type
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
		for {
			select {
			case <-ctx.Done():
				fmt.Println("Done")
				return
			case inputBytes := <-dataChan:
				fmt.Printf("%+v\n", inputBytes)
				outputStruct := reflect.New(outputType).Elem()
				err = binary.Read(bytes.NewBuffer(inputBytes), bcc.GetHostByteOrder(), outputStruct.Addr().Interface())
				if err != nil {
					errChan <- fmt.Errorf("tracer.go: Error parsing output: %s\n", err)
					return
				}
				fmt.Printf("%+v\n", outputStruct)
			}
		}
		perfMap.Stop()
	default:
		errChan <- fmt.Errorf("tracer.go: Output type %s is not supported",
			output.Type)
	}
}

// Use reflect package to live build a new type for binary output unmarshalling
func buildStructFromArray(inputArray []config.BPFOutputFormat) (reflect.Type, error) {

	var fields []reflect.StructField
	var intSize int
	var err error
	for _, item := range inputArray {
		isArray := false
		itemTypeString := item.Type
		if strings.ContainsAny(itemTypeString, "[") {
			isArray = true
			sizeArr := strings.Split(strings.Split(itemTypeString, "]")[0], "[")
			size := sizeArr[len(sizeArr)-1]
			intSize, err = strconv.Atoi(size)
			if err != nil {
				return nil, fmt.Errorf("tracer.go: Error converting size %s to int", size)
			}
			// Overwrite itemTypeString with non-array name
			itemTypeString = strings.Split(itemTypeString, "[")[0]
		}
		var itemType interface{}
		switch itemTypeString {
		case "u64":
			itemType = uint64(0)
		case "u32":
			itemType = uint32(0)
		case "int":
			itemType = int(0)
		case "int32":
			itemType = int32(0)
		case "char":
			itemType = byte(0)
		default:
			return nil, fmt.Errorf("tracer.go: Format type %s is not supported", item.Type)
		}
		if isArray {
			fields = append(fields, reflect.StructField{
				Name: strings.Title(item.Name), Type: reflect.ArrayOf(intSize,
					reflect.TypeOf(itemType)),
			})
		} else {
			fields = append(fields, reflect.StructField{
				Name: strings.Title(item.Name), Type: reflect.TypeOf(itemType),
			})
		}
	}
	newType := reflect.StructOf(fields)
	return newType, nil
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
		pollOutputMaps(ctx, output, m, errChan)
	}
}
