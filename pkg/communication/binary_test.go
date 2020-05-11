package communication

import (
	"reflect"
	"strings"
	"testing"

	"github.com/olcf/greggd/pkg/config"
)

func TestBuildStructFromArray(t *testing.T) {
	expected := reflect.StructOf([]reflect.StructField{
		reflect.StructField{Name: strings.Title("id"),
			Type: reflect.TypeOf(uint64(0))},
		reflect.StructField{Name: strings.Title("pid"),
			Type: reflect.TypeOf(uint32(0))},
		reflect.StructField{Name: strings.Title("uid"),
			Type: reflect.TypeOf(uint32(0))},
		reflect.StructField{Name: strings.Title("ret"),
			Type: reflect.TypeOf(int32(0))},
		reflect.StructField{Name: strings.Title("comm"),
			Type: reflect.ArrayOf(16, reflect.TypeOf(byte(0)))},
	})
	input := []config.BPFOutputFormat{
		config.BPFOutputFormat{Name: "id", Type: "u64"},
		config.BPFOutputFormat{Name: "pid", Type: "u32"},
		config.BPFOutputFormat{Name: "uid", Type: "u32"},
		config.BPFOutputFormat{Name: "ret", Type: "int32"},
		config.BPFOutputFormat{Name: "comm", Type: "char[16]"},
	}
	actual, err := BuildStructFromArray(input)
	if err != nil {
		t.Errorf("Error got trying to build struct: %v", err)
	}
	if expected != actual {
		t.Errorf("Output of BuildStructFromArray doesn't equal expected.")
	}
}

func TestWriteBinaryToStruct(t *testing.T) {
	tables := []struct {
		inType      reflect.Type
		inBytes     []byte
		expectedVal reflect.Value
		setVal      interface{}
	}{
		// Test if it can parse 56
		{
			reflect.TypeOf(int8(0)),
			[]byte{56},
			reflect.New(reflect.TypeOf(int8(0))).Elem(),
			int8(56),
		},
		// Test if it can parse 100
		{
			reflect.TypeOf(int64(0)),
			[]byte{100, 0, 0, 0, 0, 0, 0, 0, 0},
			reflect.New(reflect.TypeOf(int64(0))).Elem(),
			int64(100),
		},
		// Test if it can parse 123456
		{
			reflect.TypeOf(uint64(0)),
			[]byte{64, 226, 1, 0, 0, 0, 0, 0},
			reflect.New(reflect.TypeOf(uint64(0))).Elem(),
			uint64(123456),
		},
		// Test if it can parse -153
		{
			reflect.TypeOf(int64(0)),
			[]byte{256 - 153, 255, 255, 255, 255, 255, 255, 255, 255},
			reflect.New(reflect.TypeOf(int64(0))).Elem(),
			int64(-153),
		},
	}

	for _, tbl := range tables {
		tbl.expectedVal.Set(reflect.ValueOf(tbl.setVal))

		outVal, err := writeBinaryToStruct(tbl.inBytes, tbl.inType)
		if err != nil {
			t.Errorf("Error got trying to write binary: %v", err)
		}
		if outVal.Interface() != tbl.expectedVal.Interface() {
			t.Errorf("Output value doesn't match expected from binary: %+v != %+v",
				outVal.Interface(), tbl.expectedVal.Interface())
		}
	}
}
