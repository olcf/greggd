package communication

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/olcf/greggd/config"
)

// Use reflect package to build a new type for binary output unmarshalling at
// runtime
func BuildStructFromArray(inputArray []config.BPFOutputFormat) (reflect.Type,
	error) {

	var fields []reflect.StructField
	var intSize int
	var err error
	// Use data types from array to build struct fields
	for _, item := range inputArray {
		isArray := false
		intSize = 0
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
