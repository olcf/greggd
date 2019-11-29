package tracer

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/olcf/greggd/config"
)

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
	case "key", "pid", "uid", "fname", "process":
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
func formatOutput(mapName string, outputStruct reflect.Value,
	outputFormat []config.BPFOutputFormat) (string, error) {

	tags := make(map[string]interface{})
	fields := make(map[string]interface{})

	var sb strings.Builder

	var err error
	var value interface{}
	for i := 0; i < outputStruct.NumField(); i++ {
		// Get data type and value of the field
		fieldKind := outputStruct.Type().Field(i)
		fieldVal := outputStruct.Field(i)
		fieldName := strings.ToLower(fieldKind.Name)
		fieldFormat := outputFormat[i]

		// If an array, assume byte array
		if fieldKind.Type.Kind() == reflect.Array {

			// Convert byte array to string
			bytesVal := fieldVal.Slice(0, fieldVal.Len()).Bytes()
			n := bytes.IndexByte(bytesVal, 0)
			value = string(bytesVal[:n])

			// Filter strings
			if len(value.(string)) == 0 {
				fmt.Sprintf("  Returning early. StringVal: %s\n", value)
				return "", err
			}
		} else {
			value = fieldVal
		}

		// Filter values
		value, err = filterValues(value, fieldFormat)
		if err != nil {
			return "", fmt.Errorf("tracer.go: Error filtering values: %s\n", err)
		}
		if value == nil {
			return "", nil
		}

		_, valueIsString := value.(string)
		if fieldFormat.IsTag {
			if valueIsString {
				tags[fieldName] = formatTag(value.(string))
			} else {
				tags[fieldName] = value
			}
		} else {
			if valueIsString {
				fields[fieldName] = escapeField(value.(string))
			} else {
				fields[fieldName] = value
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

func filterValues(value interface{},
	outFormat config.BPFOutputFormat) (interface{}, error) {

	// No filter, return
	if outFormat.CompiledFilter == nil {
		return value, nil
	}

	// If filter, try match. If error throw
	filterMatch, err := outFormat.CompiledFilter.Match(value)
	if err != nil {
		return nil, fmt.Errorf(
			"tracer.go: Error matching value %v against filter %v: %v\n",
			value, outFormat.CompiledFilter, err)
	}

	// If there's a match, return nothing
	if filterMatch {
		return nil, nil
	}

	// Value doesn't match filter. Return
	return value, nil
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
