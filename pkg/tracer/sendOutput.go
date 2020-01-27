package tracer

import (
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"time"

	"github.com/olcf/greggd/pkg/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

func readPerfChannel(ctx context.Context, outType reflect.Type,
	dataChan chan []byte, outputChan chan config.SocketInput, errChan chan error,
	output *config.BPFOutput, globals config.GlobalOptions,
	mapName string) {

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Done")
			return
		case inputBytes := <-dataChan:
			tags, fields := make(map[string]string), make(map[string]string)
			outputChan <- config.SocketInput{
				MeasurementName: mapName, Fields: fields, Tags: tags,
				Bytes: inputBytes, Output: output, Type: outType,
			}
		}
	}
}

func iterateHashMap(ctx context.Context, table *bcc.Table,
	outType reflect.Type, socketChan chan config.SocketInput, errChan chan error,
	output *config.BPFOutput, globals config.GlobalOptions) {

	sleepDuration, err := time.ParseDuration(output.Poll)
	if err != nil {
		errChan <- fmt.Errorf("tracer.go: Error parsing poll time %s: %s\n",
			output.Poll, err)
		return
	}

	ticker := time.NewTicker(sleepDuration)
	defer ticker.Stop()

	// Infinite loop, call loopHashMap every polling period
	loopHashMap(ctx, table, outType, socketChan, errChan, output, globals)
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Done")
			return
		case <-ticker.C:
			loopHashMap(ctx, table, outType, socketChan, errChan, output, globals)
		}
	}

	return
}

func loopHashMap(ctx context.Context, table *bcc.Table,
	outType reflect.Type, socketChan chan config.SocketInput, errChan chan error,
	output *config.BPFOutput, globals config.GlobalOptions) {

	// Get table iterator and iterate over keys
	tableIter := table.Iter()

	for {
		// Iterate. Break if no more keys
		if !tableIter.Next() {
			break
		}
		// No idea why this some keys are less than uint64 length. Skip if it is
		if len(tableIter.Key()) < 8 {
			fmt.Printf("Key is less than full length: %v:%s\n", tableIter.Key(),
				len(tableIter.Key()))
			break
		}

		// Read value
		val, err := table.Get(tableIter.Key())
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error getting key %s from table: %s\n",
				tableIter.Key(), table.ID(), tableIter.Err())
			return
		}

		// Clear the value if desired
		if output.Clear {
			clearBytes := make([]byte, len(val))
			err = table.Set(tableIter.Key(), clearBytes)
			if err != nil {
				errChan <- fmt.Errorf(
					"tracer.go: Error clearing key %s from table: %s\n", tableIter.Key(),
					table.ID(), err)
				return
			}
		}

		// Save key as a field
		fields := map[string]string{"hash_key": fmt.Sprintf("%d",
			binary.LittleEndian.Uint64(tableIter.Key()))}

		// Write data to struct and send it on
		socketChan <- config.SocketInput{
			MeasurementName: table.ID(), Fields: fields, Tags: map[string]string{},
			Bytes: val, Output: output, Type: outType,
		}
	}
}
