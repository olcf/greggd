package tracer

import (
	"context"
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
				DataBytes: inputBytes, OutputConfig: output, DataType: outType,
			}
		}
	}
}

func iterateHashMap(ctx context.Context, table *bcc.Table,
	outType reflect.Type, keyType reflect.Type,
	socketChan chan config.SocketInput, errChan chan error,
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
	loopHashMap(ctx, table, outType, keyType, socketChan, errChan, output,
		globals)
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Done")
			return
		case <-ticker.C:
			loopHashMap(ctx, table, outType, keyType, socketChan, errChan, output,
				globals)
		}
	}
}

func loopHashMap(ctx context.Context, table *bcc.Table,
	outType reflect.Type, keyType reflect.Type,
	socketChan chan config.SocketInput, errChan chan error,
	output *config.BPFOutput, globals config.GlobalOptions) {

	// Get table iterator and iterate over keys
	tableIter := table.Iter()

	for {
		// Iterate. Break if no more keys
		if !tableIter.Next() {
			fmt.Printf("Reached end of map\n")
			break
		}
		// No idea why this some keys are less than uint64 length. Skip if it is
		// It's b/c some keys are less than uint64 dumb dumb
		if len(tableIter.Key()) < int(keyType.Size()) {
			fmt.Printf("Key is less than full length: %v:%v\n", tableIter.Key(),
				len(tableIter.Key()))
			break
		}

		// Read value
		val, err := table.Get(tableIter.Key())
		if err != nil {
			errChan <- fmt.Errorf("tracer.go: Error getting key %s from table %s: %s\n",
				tableIter.Key(), table.ID(), tableIter.Err())
			return
		}

		// Clear the value if desired
		if output.Clear {
			clearBytes := make([]byte, len(val))
			err = table.Set(tableIter.Key(), clearBytes)
			if err != nil {
				errChan <- fmt.Errorf(
					"tracer.go: Error clearing key %s from table %s: %s\n", tableIter.Key(),
					table.ID(), err)
				return
			}
		}

		// Write data to struct and send it on
		socketChan <- config.SocketInput{
			MeasurementName: table.ID(), Fields: map[string]string{},
			Tags: map[string]string{}, KeyData: tableIter.Key(), KeyType: keyType,
			DataType: outType, DataBytes: val, OutputConfig: output,
		}
	}
}
