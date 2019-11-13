package main

import (
	"flags"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	config "github.com/olcf/greggd/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

var (
	configPath = flag.String("config", "/etc/greggd.conf",
		"Path to config file. Defaults to `/etc/greggd.conf`")
)

func main() {
	// Overwrite the flag packages' usage function so we can give extra info about
	// greggd
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), `

Greggd collects and exports low-level tracing data from the eBPF in-kernel
virtual machine to a user defined socket. It compilies and loads configured
user-programs into the eBPF VM while polling memory tables for performance
events.

	`)
		flag.PrintDefaults()
	}

	// Parse flags
	flags.Parse()

	source, err := ioutil.ReadFile(flags.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "main.go: Failed to read config from %s: %s\n",
			flags.configPath, err)
		os.Exit(1)
	}

	// Compile a bpf module, load it into the kernel. Pass empty c flags to bcc
	// during compilation
	m := bcc.NewModule(string(source), []string{})
	// Close all kprobes and unload the ebpf module from the kernel
	defer m.Close()

	// Load in the C func hello_world as a kernel probe
	// Return fd of where the probe was loaded into
	helloWorldProbeFd, err := m.LoadKprobe("hello_world")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hello_world kprobe: %s\n", err)
		os.Exit(1)
	}

	// Attach the loaded kprobe to the sys_clone syscall
	err = m.AttachKprobe("sys_sync", helloWorldProbeFd)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Failed to attach hello_world kprobe to sys_clone: %s\n", err)
		os.Exit(1)
	}

	// Get reference to BPF table. Get the table's id by name, and load it from
	// the module
	table := bcc.NewTable(m.TableId("events"), m)
	// This table is a perf map. Create a channel to receive data from it, and
	// cast the table as a perf map
	bpfChan := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, bpfChan)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Failed to build perf map from events table: %s\n", err)
		os.Exit(1)
	}

	// Golang goodness. Build a go routine to print events output from the perf
	// map
	go func() {
		for {
			rawData := <-bpfChan
			fmt.Printf("%s", rawData)
		}
	}()

	// Open channel to catch exit signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Start the perf map. Polls perf map memory and sends events to channel
	perfMap.Start()
	// Block until exit signal called
	<-sig
	// Stop polling perf map and close channel when exit called
	perfMap.Start()
}
