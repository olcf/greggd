package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	config "github.com/olcf/greggd/config"
)

var (
	configPath = flag.String("config", "/etc/greggd.conf",
		"Path to config file. Defaults to `/etc/greggd.conf`")
)

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

	fmt.Printf(configStruct.SocketPath)

}
