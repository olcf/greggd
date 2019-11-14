package config

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v2"
)

type GreggdConfig struct {
	// Socket we're writing data out to
	SocketPath string `yaml:"socketPath"`
	// List of the eBPF programs managed by this app
	Programs []BPFProgram
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
	// Format of the struct
	Format []BPFOutputFormat `yaml:"format"`
}

type BPFOutputFormat struct {
	// Name of the value in the struct
	Name string `yaml:"name"`
	// Type of the value
	Type string `yaml:"type"`
}

func ParseConfig(input io.Reader) (*GreggdConfig, error) {
	buf := bytes.NewBuffer([]byte{})
	_, err := buf.ReadFrom(input)
	if err != nil {
		return nil, fmt.Errorf("\nconfig.go: Error reading input to buffer:\n%s",
			err)
	}

	configStruct := GreggdConfig{}
	err = yaml.Unmarshal(buf.Bytes(), &configStruct)
	if err != nil {
		return nil, fmt.Errorf(
			"\nconfig.go: Error unmarshalling config into struct:\n%s", err)
	}

	return &configStruct, nil
}
