package config

import (
	"bytes"
	"fmt"
	"io"

	"github.com/onsi/gomega/types"
	"gopkg.in/yaml.v2"
)

type GreggdConfig struct {
	// Store global options for development
	Globals GlobalOptions
	// List of the eBPF programs managed by this app
	Programs []BPFProgram
}

type GlobalOptions struct {
	// Socket we're writing data out to
	SocketPath string `yaml:"socketPath"`
	// Format for verbose output.
	VerboseFormat string `yaml:"verboseFormat"`
	// Log measurements to stdout. Overwritten by command line value if set
	Verbose bool `yaml:"verbose"`
}

type BPFProgram struct {
	// Source of the eBPF program to load in. Will be compilied by BCC into eBPF
	// byte code. Should point to a .c file
	Source string `yaml:"source"`
	// Events to trace with this eBPF program
	Events []BPFEvent `yaml:"events"`
	// Maps/tables to poll for this program. Should have the output data from the
	// tracing program
	Outputs []BPFOutput `yaml:"outputs"`
}

type BPFEvent struct {
	// Type of event this is. Either Kprobe, Kretprobe, etc...
	Type string `yaml:"type"`
	// Name of the function to load into eBPF VM for this event
	LoadFunc string `yaml:"loadFunc"`
	// What eBPF object we're attaching this function to
	AttachTo string `yaml:"attachTo"`
}

type BPFOutput struct {
	// ID of the table to watch
	Id string `yaml:"id"`
	// What table type this is
	Type string `yaml:"type"`
	// If not perf output, how often to poll output
	Poll string `yaml:"poll"`
	// Should we clear hash on poll
	Clear bool `yaml:"clear"`
	// Format of the struct
	Format []BPFOutputFormat `yaml:"format"`
}

type BPFOutputFormat struct {
	// Name of the value in the struct
	Name string `yaml:"name"`
	// Type of the value
	Type string `yaml:"type"`
	// Golang format string to save value as. Defaults to %v
	FormatString string `yaml:"formatString"`
	// Set if this should be a tag
	IsTag bool `yaml:"isTag"`
	// Filter to apply to values
	Filter interface{} `yaml:"filter"`
	// Filters get compiled by <func> and iterated over to check
	CompiledFilter types.GomegaMatcher
}

func ParseConfig(input io.Reader) (*GreggdConfig, error) {
	buf := bytes.NewBuffer([]byte{})
	_, err := buf.ReadFrom(input)
	if err != nil {
		return nil, fmt.Errorf("config.go: Error reading input to buffer:\n%s",
			err)
	}

	configStruct := GreggdConfig{}
	err = yaml.Unmarshal(buf.Bytes(), &configStruct)
	if err != nil {
		return nil, fmt.Errorf(
			"config.go: Error unmarshalling config into struct:\n%s", err)
	}

	// Compile filters into go mega filters. Need to edit the struct for each
	// filter. Iterate down to formats, using pointers to each item. Add compiled
	// filter to format
	for iProg := range configStruct.Programs {
		prog := &configStruct.Programs[iProg]
		for iOutput := range prog.Outputs {
			output := &prog.Outputs[iOutput]
			for iFormat := range output.Format {
				format := &output.Format[iFormat]
				// If there's no format filter, skip
				if format.Filter == nil {
					continue
				}
				compiledFilter, err := compileGomegaMatcher(format.Filter)
				if err != nil {
					return nil, fmt.Errorf(
						"config.go: Error compiling filter %v for %s: %s\n", format.Filter,
						prog.Source, err)
				}
				format.CompiledFilter = compiledFilter
			}
		}
	}

	return &configStruct, nil
}
