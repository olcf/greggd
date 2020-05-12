package communication

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olcf/greggd/pkg/config"
)

func TestBytesToSocket(t *testing.T) {
	// Set up system vars
	ctx := context.Background()
	server, client := net.Pipe()
	client.SetDeadline(time.Now().Add(time.Second))
	server.SetDeadline(time.Now().Add(time.Second))
	defer server.Close()
	defer client.Close()
	errChan := make(chan error)
	defer close(errChan)

	// Set up test table
	tables := []struct {
		expectedOutput string
		socketInput    config.SocketInput
	}{
		{
			// Basic test to make sure everything works
			"bpf,sensor=test key=25601,testdata=16836864",
			config.SocketInput{
				MeasurementName: "test", Fields: map[string]string{},
				Tags: map[string]string{}, KeyType: reflect.TypeOf(uint32(0)),
				KeyData: []byte{1, 100, 0, 0},
				DataType: reflect.StructOf([]reflect.StructField{{Name: "Testdata",
					Type: reflect.TypeOf(uint32(0))}}), DataBytes: []byte{0, 233, 0, 1},
				OutputConfig: &config.BPFOutput{
					Id: "faketable", Type: "faketable", Key: config.BPFOutputFormat{
						Name: "key", CompiledType: reflect.TypeOf(uint32(0))},
					Format: []config.BPFOutputFormat{{Name: "testdata",
						CompiledType: reflect.StructOf([]reflect.StructField{{
							Name: "Testdata", Type: reflect.TypeOf(uint32(0))}}),
					}}}},
		},
	}

	// Run the test
	for _, tbl := range tables {
		// Read output from socket byte by byte until newline
		var wg sync.WaitGroup
		actualOutput := bytes.NewBuffer([]byte{})
		go func() {
			tmp := make([]byte, 1)
			wg.Add(1)
			for {
				_, err := server.Read(tmp)
				if err != nil {
					t.Errorf("Error got trying to read from connection: %v", err)
				}
				actualOutput.Write(tmp)
				if tmp[0] == '\n' {
					break
				}
			}
			wg.Done()
		}()
		// Check the error channel output from socket
		go func() {
			wg.Add(1)
			select {
			case err := <-errChan:
				if err != nil {
					t.Errorf("Error got trying to read from connection: %v", err)
				}
			default:
			}
			wg.Done()
		}()
		// Really run the test
		bytesToSocket(ctx, tbl.socketInput, errChan, config.GlobalOptions{}, client)
		wg.Wait()

		// Parse the output
		stringOutput := actualOutput.String()
		// Output is filtered through a map internally, not guaranteed to have same
		// output consistently. Sort each section of output and join
		spaceSplit := strings.Split(stringOutput, " ")
		var sortedOutputArr []string
		for _, statement := range spaceSplit {
			commaSplit := strings.Split(statement, ",")
			sort.Strings(commaSplit)
			sortedOutputArr = append(sortedOutputArr, strings.Join(commaSplit, ","))
		}
		sortedOutputString := strings.Join(sortedOutputArr, " ")
		// Drop timestamp field
		lastSpace := strings.LastIndex(sortedOutputString, " ")
		// Compare values
		if sortedOutputString[:lastSpace] != tbl.expectedOutput {
			t.Errorf("String output '%v' does not match expected value '%v'",
				sortedOutputString[:lastSpace], tbl.expectedOutput)
		}
	}
}
