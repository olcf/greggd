package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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
			value = escapeField(value.(string))
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
