package communication

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/olcf/greggd/pkg/config"
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
func Max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

// Function to read in and parse values. Recursable
func getFieldValue(fieldVal reflect.Value, fieldFormat config.BPFOutputFormat) (string, error) {
	var sb strings.Builder
	var err error
	var value interface{}

	// If an array, assume byte array
	if fieldVal.Kind() == reflect.Array {
		var subBuilder strings.Builder
		// Check if array of arrays or just an array
		if fieldVal.Index(0).Kind() == reflect.Array {
			childFieldFormat := fieldFormat
			// Overload child formatting
			childFieldFormat.FormatString = "%s"
			for i := 0; i < fieldVal.Len(); i++ {
				value, err = getFieldValue(fieldVal.Index(i), childFieldFormat)
				if err != nil {
					return "", fmt.Errorf("tracer.go: Error getting field values: %s\n", err)
				}
				if len(value.(string)) == 0 {
					break
				}
				if i != 0 {
					subBuilder.WriteString(" ")
				}
				subBuilder.WriteString(value.(string))
			}
			value = subBuilder.String()
		} else {

			// Convert byte array to string
			bytesVal := fieldVal.Slice(0, fieldVal.Len()).Bytes()
			n := bytes.IndexByte(bytesVal, 0)
			value = string(bytesVal[:Max(n, 0)])
		}

		// Filter strings on length
		if len(value.(string)) == 0 {
			return "", nil
		}

		// Add escaped quotes to strings
		value = value.(string)
		if !fieldFormat.IsTag && fieldFormat.FormatString == "" {
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
	sb.WriteString(stringValue)

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

// Loop over each struct, formatting byte arrays to strings, filtering output,
// marking as tag or measurement field. Return influx formatted measurement
func FormatOutput(mapName string, outputStruct reflect.Value,
	tags map[string]string, fields map[string]string,
	outputFormat []config.BPFOutputFormat) (string, error) {

	var err error
	// Iterate over values in struct. Format and filter data types and append to
	// either tag or field maps
	for i := 0; i < outputStruct.NumField(); i++ {
		// Get data type and value of the field
		fieldKind := outputStruct.Type().Field(i)
		fieldVal := outputStruct.Field(i)
		fieldName := strings.ToLower(fieldKind.Name)
		fieldFormat := outputFormat[i]

		stringValue, err := getFieldValue(fieldVal, fieldFormat)
		if err != nil {
			return "", fmt.Errorf("tracer.go: Error getting field values: %s\n", err)
		}
		// Filter strings on length
		if len(stringValue) == 0 {
			return "", err
		}

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
