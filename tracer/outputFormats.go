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
	"strings"
	"sync"
	"time"

	"github.com/olcf/greggd/config"
	bcc "github.com/josephvoss/gobpf/bcc"
)

func readPerfChannel(ctx context.Context, outType reflect.Type,
	dataChan chan []byte, errChan chan error, verbose bool, mapName string,
	c net.Conn, mux *sync.Mutex) {

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Done")
			return
		case inputBytes := <-dataChan:
			outputStruct := reflect.New(outType).Elem()
			err := binary.Read(bytes.NewBuffer(inputBytes), bcc.GetHostByteOrder(),
				outputStruct.Addr().Interface())
			if err != nil {
				errChan <- fmt.Errorf("tracer.go: Error parsing output: %s\n", err)
				return
			}
			// Get influx-like output
			outputString := formatOutput(mapName, outputStruct)
			// Get raw JSON output, does not convert byte arrays to strings
			outputJson, _ := json.Marshal(outputStruct.Interface())

			sendOutputToSock(outputString, errChan, mux, c)
			if verbose {
				fmt.Println(outputString)
				fmt.Printf("%s\n", outputJson)
			}
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

// Loop over each struct, write output in Influx-like format. Convert arrays to
// strings. Assumes all arrays are byte strings.
func formatOutput(mapName string, outputStruct reflect.Value) string {
	var sb strings.Builder
	sb.WriteString(mapName)
	sb.WriteString(" ")
	// Loop over struct fields
	for i := 0; i < outputStruct.NumField(); i++ {
		// Get data type and value of the field
		fieldKind := outputStruct.Type().Field(i)
		fieldVal := outputStruct.Field(i)
		// If it's an array, assume it's a byte array. Convert to string
		if fieldKind.Type.Kind() == reflect.Array {
			stringVal := string(fieldVal.Slice(0, fieldVal.Len()).Bytes())
			sb.WriteString(fmt.Sprintf("%v=\"%v\"", fieldKind.Name, stringVal))
			// Otherwise, just write the key name and the value
		} else {
			sb.WriteString(fmt.Sprintf("%v=%v", fieldKind.Name, fieldVal))
		}
		// If we're not the last entry, add separators. If we are, add timestamp
		if i == outputStruct.NumField()-1 {
			sb.WriteString(fmt.Sprintf(" %d\n", time.Now().Unix()))
		} else {
			sb.WriteString(",")
		}
	}
	return sb.String()
}

// Use reflect package to build a new type for binary output unmarshalling at
// runtime
func buildStructFromArray(inputArray []config.BPFOutputFormat) (reflect.Type,
	error) {

	var fields []reflect.StructField
	var intSize int
	var err error
	// Use data types from array to build struct fields
	for _, item := range inputArray {
		isArray := false
		itemTypeString := item.Type
		// Figure out if this is an array. Set isArray and get array size
		if strings.ContainsAny(itemTypeString, "[") {
			isArray = true
			sizeArr := strings.Split(strings.Split(itemTypeString, "]")[0], "[")
			size := sizeArr[len(sizeArr)-1]
			intSize, err = strconv.Atoi(size)
			if err != nil {
				return nil, fmt.Errorf("tracer.go: Error converting size %s to int",
					size)
			}
			// Overwrite itemTypeString with non-array name
			itemTypeString = strings.Split(itemTypeString, "[")[0]
		}
		// Get item type
		var itemType interface{}
		switch itemTypeString {
		case "u64":
			itemType = uint64(0)
		case "u32":
			itemType = uint32(0)
		case "int":
			itemType = int(0)
		case "int32":
			itemType = int32(0)
		case "char":
			itemType = byte(0)
		default:
			return nil, fmt.Errorf("tracer.go: Format type %s is not supported",
				item.Type)
		}
		// Create struct fields for correct data type
		if isArray {
			fields = append(fields, reflect.StructField{
				Name: strings.Title(item.Name), Type: reflect.ArrayOf(intSize,
					reflect.TypeOf(itemType)),
			})
		} else {
			fields = append(fields, reflect.StructField{
				Name: strings.Title(item.Name), Type: reflect.TypeOf(itemType),
			})
		}
	}
	// Build struct
	return reflect.StructOf(fields), nil
}
