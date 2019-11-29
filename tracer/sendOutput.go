package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"

	"github.com/olcf/greggd/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

func readPerfChannel(ctx context.Context, outType reflect.Type,
	dataChan chan []byte, errChan chan error,
	outputFormat []config.BPFOutputFormat, globals config.GlobalOptions,
	mapName string, c net.Conn, mux *sync.Mutex) {

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Done")
			return
		case inputBytes := <-dataChan:
			readBytesAndOutput(ctx, outType, inputBytes, map[string]string{}, errChan,
				outputFormat, globals, mapName, c, mux)
		}
	}
}

func iterateHashMap(ctx context.Context, table *bcc.Table,
	outType reflect.Type, errChan chan error, outputFormat []config.BPFOutputFormat,
	globals config.GlobalOptions, c net.Conn, mux *sync.Mutex) {

	// Get table iterator and iterate over keys
	tableIter := table.Iter()

	for {
		// Write values to byte buffer
		buf := bytes.NewBuffer([]byte{})

		// Iterate. Break if no more keys
		if !tableIter.Next() {
			// Should we send this error on, or just break and move on?
			//errChan <- fmt.Errorf("tracer.go: Error iterating table %s: %s\n",
			//	table.ID(), tableIter.Err())
			//return
			break
		}
		val, err := table.Get(tableIter.Key())
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error getting key %s from table: %s\n",
				tableIter.Key(), table.ID(), tableIter.Err())
			return
		}
		// Save key as a tag
		keyAsString := binary.LittleEndian.Uint64(tableIter.Key())
		tags := map[string]string{"hash_key": strconv.FormatUint(keyAsString, 10)}
		// Write to buffer. Should also check that write size == reflect size
		_, err = buf.Write(val)
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error writing binary to buffer: %s\n",
				err)
			return
		}
		// Write data to struct and send it on
		readBytesAndOutput(ctx, outType, buf.Bytes(), tags, errChan, outputFormat,
			globals, table.ID(), c, mux)
	}

	return

}

// Read in data, write to a new struct object of reflect type, format and send
// to socket
func readBytesAndOutput(ctx context.Context, outType reflect.Type,
	inBytes []byte, tags map[string]string, errChan chan error,
	outputFormat []config.BPFOutputFormat, globals config.GlobalOptions,
	mapName string, c net.Conn, mux *sync.Mutex) {

	// Build out struct
	outputStruct := reflect.New(outType).Elem()

	// Load input bytes into output struct
	err := binary.Read(bytes.NewBuffer(inBytes), bcc.GetHostByteOrder(),
		outputStruct.Addr().Interface())
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error parsing output: %s\n", err)
		return
	}

	// Get influx-like output
	outputString, err := formatOutput(mapName, outputStruct, outputFormat)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error formatting output: %s\n", err)
	}

	sendOutputToSock(outputString, errChan, mux, c)
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

func sendOutputToSock(outString string, errChan chan error, mux *sync.Mutex,
	c net.Conn) error {

	mux.Lock()
	defer mux.Unlock()

	_, err := c.Write([]byte(outString))
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error sending output to socket: %s\n",
			err)
	}
	return nil
}
