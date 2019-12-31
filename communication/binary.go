package communication

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"

	"github.com/olcf/greggd/config"
)

// Use reflect package to build a new type for binary output unmarshalling at
// runtime
func BuildStructFromArray(inputArray []config.BPFOutputFormat) (reflect.Type,
	error) {

	var fields []reflect.StructField
	var intSize, intInnerSize int
	// Use data types from array to build struct fields
	for _, item := range inputArray {
		isArrayofArrays := false
		isArray := false
		intSize = 0
		itemTypeString := item.Type
		// Figure out if this is an array. Set isArray and get array size
		switch strings.Count(itemTypeString, "[") {
		case 1:
			isArray = true
			itemTypeString = strings.ReplaceAll(strings.ReplaceAll(itemTypeString, "[", " "), "]", " ")
			_, err := fmt.Sscanf(itemTypeString, "%s %d ", &itemTypeString, &intSize)
			if err != nil {
				return nil, fmt.Errorf("tracer.go: Error converting %s to array: %s", itemTypeString, err)
			}
		case 2:
			isArrayofArrays = true
			itemTypeString = strings.ReplaceAll(strings.ReplaceAll(itemTypeString, "[", " "), "]", " ")
			_, err := fmt.Sscanf(itemTypeString, "%s %d  %d ", &itemTypeString, &intSize, &intInnerSize)
			if err != nil {
				return nil, fmt.Errorf("tracer.go: Error converting %s to array of arrays: %s", itemTypeString, err)
			}
		}
		// Get item type
		var itemType interface{}
		switch itemTypeString {
		case "u64":
			itemType = uint64(0)
		case "u32":
			itemType = uint32(0)
		case "u16":
			itemType = uint16(0)
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
		if isArrayofArrays {
			fields = append(fields, reflect.StructField{
				Name: strings.Title(item.Name), Type: reflect.ArrayOf(intSize,
					reflect.ArrayOf(intInnerSize, reflect.TypeOf(itemType))),
			})
		} else if isArray {
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

func writeBinaryToStruct(inBytes []byte, outType reflect.Type) (*reflect.Value,
	error) {

	// Check if input size matches output size
	if uint64(len(inBytes)) != uint64(outType.Size()) {
		return nil, fmt.Errorf(
			"tracer.go: Input byte slice (%v) != output struct size: (%v)\n",
			len(inBytes), uint64(outType.Size()),
		)
	}

	// Build out struct
	outputStruct := reflect.New(outType).Elem()

	// Load input bytes into output struct
	err := binary.Read(bytes.NewBuffer(inBytes), binary.LittleEndian,
		outputStruct.Addr().Interface())
	if err != nil {
		return nil, fmt.Errorf("tracer.go: Error parsing output: %s\n", err)
	}

	return &outputStruct, nil
}
