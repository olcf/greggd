package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/olcf/greggd/pkg/communication"
	"github.com/olcf/greggd/pkg/config"
	"github.com/olcf/greggd/pkg/tracer"
)

var (
	configPath = flag.String("config", "/etc/greggd.conf",
		"Path to config file. Defaults to `/etc/greggd.conf`")
	verbose = flag.Bool("v", false,
		"Log messages to stdout. Can also be set in the config file")
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

	// If cli says verbose and config doesn't, set config to verbose
	if *verbose && !configStruct.Globals.Verbose {
		configStruct.Globals.Verbose = true
	}

	// Create background context with cancel function
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Open channel to catch exit signals
	sig := make(chan os.Signal, 1)
	defer close(sig)

	signal.Notify(sig, os.Interrupt, os.Kill)

	// Open channel to catch goroutine errors
	errChan := make(chan error)
	defer close(errChan)

	// Open channel to send data
	dataChan := make(chan config.SocketInput)
	defer close(dataChan)

	// Create wait group to watch goroutine progress
	var wg sync.WaitGroup

	// Create goroutine for sending to socket
	wg.Add(1)
	go communication.BytesToSock(ctx, dataChan, errChan, configStruct.Globals,
		&wg)

	// Create goroutine for each program, increment number of running procs, do
	// the work
	for _, program := range configStruct.Programs {
		wg.Add(1)
		go tracer.Trace(ctx, program, dataChan, errChan, configStruct.Globals,
			&wg)
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
