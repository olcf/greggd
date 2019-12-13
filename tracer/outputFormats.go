package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
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

	sb.WriteString(strings.Replace(field, "\"", "\\\"", -1))
	return sb.String()
}

func formatTag(tag string) string {
	var sb strings.Builder

	sb.WriteString(tag)
	return sb.String()
}

// Loop over each struct, formatting byte arrays to strings, filtering output,
// marking as tag or measurement field. Return influx formatted measurement
func formatOutput(mapName string, outputStruct reflect.Value,
	tags map[string]string, outputFormat []config.BPFOutputFormat) (string,
	error) {

	fields := make(map[string]string)

	var err error
	var value interface{}
	// Iterate over values in struct. Format and filter data types and append to
	// either tag or field maps
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

			// Filter strings on length
			if len(value.(string)) == 0 {
				return "", err
			}

			// Add escaped quotes to strings
			value = value.(string)
			if !fieldFormat.IsTag {
				value = escapeField(value.(string))
				fieldFormat.FormatString = "%q"
			}
		} else if fieldFormat.IsIP {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, fieldVal.Interface().(uint32))
			value = ip
		} else {
			// Otherwise, save value as a value
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

		// Format value as string
		if fieldFormat.FormatString == "" {
			fieldFormat.FormatString = "%v"
		}
		stringValue := fmt.Sprintf(fieldFormat.FormatString, value)

		// Add to appropriate map for tag or data field
		if fieldFormat.IsTag || fieldFormat.IsIP {
			tags[fieldName] = formatTag(stringValue)
		} else {
			fields[fieldName] = stringValue
		}

	}

	// Format to influx
	return influxFormat(mapName, tags, fields), err
}

// Print key name, tags, and fields to influx format with timestamp
func influxFormat(keyName string, tags map[string]string,
	fields map[string]string) string {

	var sb strings.Builder
	// Create influx format string from key name, tags, and fields
	sb.WriteString("bpf")

	tags["sensor"] = keyName

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
		sb.WriteString(v)
	}

	sb.WriteString(fmt.Sprintf(" %d\n", time.Now().UnixNano()))

	return sb.String()
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
	var intInnerSize int
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
