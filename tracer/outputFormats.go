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
	dataChan chan []byte, errChan chan error, verbose bool, verboseFormat string,
	mapName string, c net.Conn, mux *sync.Mutex) {

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
			outputString, err := formatOutput(mapName, outputStruct)
			if err != nil {
				continue
			}

			sendOutputToSock(outputString, errChan, mux, c)
			if verbose {
				switch verboseFormat {
				case "json":
					// Get raw JSON output, does not convert byte arrays to strings
					outputJson, _ := json.Marshal(outputStruct.Interface())
					fmt.Printf("%s\n", outputJson)
				default:
					fmt.Printf(outputString)
				}
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

func formatValueField(value string) string {
	value = strings.Replace(value, ",", "\\,", -1)
	value = strings.Replace(value, "=", "\\=", -1)
	value = strings.Replace(value, " ", "\\ ", -1)
	return value
}

func escapeField(field string) string {
	var sb strings.Builder

	sb.WriteString("\"")
	sb.WriteString(strings.Replace(field, "\"", "\\\"", -1))
	sb.WriteString("\"")
	return sb.String()
}

func isTag(tag string) bool {
	switch tag {
	case "pid", "uid", "fname", "process":
		return true
	}
	return false
}

func formatTag(tag string) string {
	var sb strings.Builder

	sb.WriteString("\"")
	sb.WriteString(tag)
	sb.WriteString("\"")
	return sb.String()
}

func handleSpecialValue(field string, value interface{}) string {
	switch field {
	case "flags":
		return fmt.Sprintf("%#o", value)
	}
	return fmt.Sprintf("%v", value)
}

// Loop over each struct, write output in Influx-like format. Convert arrays to
// strings. Assumes all arrays are byte strings.
func formatOutput(mapName string, outputStruct reflect.Value) (string, error) {

	tags := make(map[string]interface{})
	fields := make(map[string]interface{})

	var sb strings.Builder

	var err error
	for i := 0; i < outputStruct.NumField(); i++ {
		fieldKind := outputStruct.Type().Field(i)
		fieldVal := outputStruct.Field(i)
		fieldName := strings.ToLower(fieldKind.Name)

		if fieldKind.Type.Kind() == reflect.Array {

			bytesVal := fieldVal.Slice(0, fieldVal.Len()).Bytes()

			n := bytes.IndexByte(bytesVal, 0)
			stringVal := string(bytesVal[:n])

			if len(stringVal) == 0 || strings.HasPrefix(stringVal, "/proc/") {
				fmt.Sprintf("  Returning early. StringVal: %s\n", stringVal)
				return "", err
			}

			if isTag(fieldName) {
				tags[fieldName] = formatTag(stringVal)
			} else {
				fields[fieldName] = escapeField(stringVal)
			}
		} else {
			if isTag(fieldName) {
				tags[fieldName] = fieldVal
			} else {
				fields[fieldName] = fieldVal
			}
		}
	}

	sb.WriteString(mapName)

	nt, nf := len(tags), len(fields)

	for k, v := range tags {
		nt--
		if nt >= 0 {
			sb.WriteString(",")
		}
		sb.WriteString(formatValueField(k))
		sb.WriteString("=")
		sb.WriteString(formatValueField(fmt.Sprintf("%v", v)))
	}
	if nt == 0 {
		sb.WriteString(" ")
	}

	for k, v := range fields {
		nf--
		if nf >= 0 && nf < (len(fields)-1) {
			sb.WriteString(",")
		}
		sb.WriteString(formatValueField(k))
		sb.WriteString("=")
		sb.WriteString(handleSpecialValue(k, v))
	}

	sb.WriteString(fmt.Sprintf(" %d\n", time.Now().Unix()))

	return sb.String(), nil
}

// Use reflect package to build a new type for binary output unmarshalling at
// runtime
func buildStructFromArray(inputArray []config.BPFOutputFormat) (reflect.Type,
	error) {

	var fields []reflect.StructField
	var intSize int
	var err error
	for _, item := range inputArray {
		isArray := false
		intSize = 0
		itemTypeString := item.Type
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
	newType := reflect.StructOf(fields)
	return newType, nil
}
