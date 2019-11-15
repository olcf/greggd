package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"

	config "github.com/olcf/greggd/config"
	tracer "github.com/olcf/greggd/tracer"
)

var (
	configPath = flag.String("config", "/etc/greggd.conf",
		"Path to config file. Defaults to `/etc/greggd.conf`")
)

// Parse the config file from input path
func parseConfig() *config.GreggdConfig {
	source, err := os.Open(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "main.go: Failed to open config file from %s: %s\n",
			*configPath, err)
		os.Exit(1)
	}

	configStruct, err := config.ParseConfig(bufio.NewReader(source))
	if err != nil {
		fmt.Fprintf(os.Stderr, "main.go: Failed to parse config file from %s: %s\n",
			*configPath, err)
		os.Exit(1)
	}

	return configStruct
}

func main() {
	// Overwrite the flag packages' usage function so we can give extra info about
	// greggd
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			`Greggd:

Greggd collects and exports low-level tracing data from the eBPF in-kernel virtual machine to a user defined socket. It compilies and loads configured user-programs into the eBPF VM while polling memory tables for performance events.`)
		fmt.Fprintf(flag.CommandLine.Output(), "\n\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Parse flags
	flag.Parse()

	// Load config
	configStruct := parseConfig()

	// Create background context with cancel function
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Open channel to catch exit signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Open channel to catch goroutine errors
	errChan := make(chan error)

	// Create wait group to watch goroutine progress
	var wg sync.WaitGroup

	// Create goroutine for each program, increment number of running procs, do
	// the work
	for _, program := range configStruct.Programs {
		wg.Add(1)
		go tracer.Trace(ctx, program, errChan, &wg)
	}

	// Watch for sig-term or errors
	select {
	case <-sig:
		fmt.Fprintf(flag.CommandLine.Output(), "Exiting\n")
	case err := <-errChan:
		fmt.Fprintf(flag.CommandLine.Output(),
			"main.go: Error received from trace: %s\n", err)
	}
	// Cancel running routines
	cancel()
	// Wait until goroutines exited
	//wg.Wait()
}
