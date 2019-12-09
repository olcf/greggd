package communication

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/olcf/greggd/config"
)

func BytesToSock(ctx context.Context, dataChan chan config.SocketInput,
	errChan chan error, globals config.GlobalOptions, wg sync.WaitGroup) {

	defer wg.Done()

	// Open socket
	c, err := net.Dial("unix", globals.SocketPath)
	if err != nil {
		errChan <- fmt.Errorf("communication.go: Error dialing socket %s: %s\n",
			globals.SocketPath, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case socketInput := <-dataChan:
			bytesToSocket(ctx, socketInput, errChan, globals, c)
		}
	}
}

func bytesToSocket(ctx context.Context, socketInput config.SocketInput,
	errChan chan error, globals config.GlobalOptions, c net.Conn) {

	// Write data to struct
	outputStruct, err := writeBinaryToStruct(socketInput.Bytes, socketInput.Type)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error writing binary to struct: %s\n",
			err)
		return
	}

	// Influx format
	outputString, err := FormatOutput(socketInput.MeasurementName, *outputStruct,
		socketInput.Tags, socketInput.Fields, socketInput.Output.Format)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error formatting output: %s\n", err)
		return
	}

	// Send to socket
	err = sendOutputToSock(outputString, c, 0, globals)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error sending output to socket: %s\n",
			err)
		return
	}

	// Verbose print
	if globals.Verbose {
		switch globals.VerboseFormat {
		case "json":
			// Get raw JSON output, does not convert byte arrays to strings
			outputJson, _ := json.Marshal(outputStruct.Interface())
			fmt.Printf("%s\n", outputJson)
		default:
			fmt.Printf(outputString)
		}
	}
}

func sendOutputToSock(outString string, c net.Conn, errCount int,
	globals config.GlobalOptions) error {

	// Drop empty strings
	if outString == "" {
		return nil
	}

	// Throw error if errCount is too high

	_, err := c.Write([]byte(outString))
	if err != nil {
		// Cancel if we tried this too much
		if errCount >= 5 {
			return fmt.Errorf(
				"communication.go: Error re-dialing socket. Failed 5 times: %s\n", err,
			)
		}

		c, err := net.Dial("unix", globals.SocketPath)
		if err != nil {
			return fmt.Errorf("communication.go: Error dialing socket %s: %s\n",
				globals.SocketPath, err)
		}
		return sendOutputToSock(outString, c, errCount+1, globals)
	}

	return nil
}
