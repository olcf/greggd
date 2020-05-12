package communication

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/olcf/greggd/pkg/config"
)

func BytesToSock(ctx context.Context, dataChan chan config.SocketInput,
	errChan chan error, globals config.GlobalOptions, wg *sync.WaitGroup) {

	defer wg.Done()

	var c net.Conn
	// Try to open socket
	err := retry(0, globals.CompiledRetryDelay, globals, func() error {
		conn, err := net.Dial("unix", globals.SocketPath)
		// Save open conn to var outside our scope
		c = conn
		return err
	})

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

	// Write key to struct
	if len(socketInput.KeyData) != 0 {
		keyData, err := writeBinaryToStruct(socketInput.KeyData,
			socketInput.KeyType)
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error writing key to struct: %s\n",
				err)
			return
		}
		keyDataString, err := getFieldValue(*keyData, socketInput.OutputConfig.Key)
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error writing key to string: %s\n",
				err)
			return
		}
		socketInput.Fields[socketInput.OutputConfig.Key.Name] = keyDataString
	}

	// Write data to struct
	outputStruct, err := writeBinaryToStruct(socketInput.DataBytes,
		socketInput.DataType)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error writing binary to struct: %s\n",
			err)
		return
	}

	// Influx format
	outputString, err := FormatOutput(socketInput.MeasurementName, *outputStruct,
		socketInput.Tags, socketInput.Fields, socketInput.OutputConfig.Format)
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

	// Try to write to socket, retrying on failures
	err := retry(0, globals.CompiledRetryDelay, globals, func() error {
		_, err := c.Write([]byte(outString))
		return err
	})

	if err != nil {
		return err
	}

	return nil
}

// Retry a given function for a number of attempts with a given delay
func retry(attempts int, delay time.Duration, globals config.GlobalOptions,
	f func() error) error {

	err := f()
	if err != nil {
		// Increment attempts. If reached max retry just return error
		attempts++
		if attempts >= globals.MaxRetryCount {
			return err
		}
		// Wait the delay. If exponential retry is set, double delay
		time.Sleep(delay)
		fmt.Println("Backing off")
		if globals.RetryExponentialBackoff {
			delay = delay * 2
		}
		// Retry the function
		return retry(attempts, delay, globals, f)
	}

	return nil

}
