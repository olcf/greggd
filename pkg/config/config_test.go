package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/onsi/gomega"
	"reflect"
	"time"
)

func TestParseConfig(t *testing.T) {
}

// Define a new type that will match the io.Reader interface
type readThrowErr int

func (readThrowErr) Read(b []byte) (n int, err error) {
	return 0, errors.New("Intentional Err")
}

// Confirm bad readers will error out
func TestParseConfigFailsOnBadReader(t *testing.T) {
	// Make fake reader that will throw Err when Read is called
	var fakeReader readThrowErr
	fakeReader = 0
	_, err := ParseConfig(fakeReader)
	if err == nil {
		t.Errorf("Faulty reader did not throw error.")
	}
}

// Confirm invalid YAML will error out
func TestParseConfigFailsOnBadYAML(t *testing.T) {
	badYAML := strings.NewReader("This isn't valid YAML")
	_, err := ParseConfig(badYAML)
	if err == nil {
		t.Errorf("Invalid input YAML did not throw error.")
	}
}

// Confirm default global values will get set
func TestParseConfigGlobalDefaults(t *testing.T) {
	emptyConfig := strings.NewReader("")
	testConfig, err := ParseConfig(emptyConfig)
	if err != nil {
		t.Errorf("Error thrown when not expected: %v", err)
		return
	}
	if testConfig.Globals.MaxRetryCount == 0 {
		t.Errorf("Default value for config not set")
	}
}

// Confirm default values for key set
func TestParseConfigProgramKeyDefaults(t *testing.T) {
	emptyConfig := strings.NewReader(`globals: {}
programs: [{source: fake, outputs: [type: fake]}]
`)
	testConfig, err := ParseConfig(emptyConfig)
	if err != nil {
		t.Errorf("Error thrown when not expected: %v", err)
		return
	}
	if len(testConfig.Programs) == 0 || len(testConfig.Programs[0].Outputs) == 0 {
		t.Errorf("Needed config arrays not populated: %v", err)
		return
	}
	if testConfig.Programs[0].Outputs[0].Key.Name == "" {
		t.Errorf("Default value for program key name not set")
	}
	if testConfig.Programs[0].Outputs[0].Key.Type == "" {
		t.Errorf("Default value for program key type not set")
	}
}

// Confirm time compliation fails with bad value
func TestParseConfigRetryTimeCompileErr(t *testing.T) {
	emptyConfig := strings.NewReader(`globals: {retryDelay: fake}`)
	_, err := ParseConfig(emptyConfig)
	if err == nil {
		t.Errorf("Invalid retry time did not throw error: %v", err)
	}
}

// Confirm time compliation returns valid time object
func TestParseConfigRetryTimeCompile(t *testing.T) {
	emptyConfig := strings.NewReader(``)
	testConfig, err := ParseConfig(emptyConfig)
	if err != nil {
		t.Errorf("Error thrown when not expected: %v", err)
		return
	}
	if testConfig.Globals.CompiledRetryDelay.String() == "" {
		t.Errorf("Compiled retryDelay is not populated time.duration object")
	}
}

func TestParseConfigCompleteExample(t *testing.T) {
	configFixture := &GreggdConfig{Globals: GlobalOptions{
		SocketPath: "/run/greggd.sock", VerboseFormat: "influx", Verbose: true,
		MaxRetryCount: 1, RetryDelay: "100ms", RetryExponentialBackoff: true},
		Programs: []BPFProgram{{Source: "/usr/share/greggd/c/opensnoop.c",
			Events: []BPFEvent{{Type: "kprobe", LoadFunc: "trace_entry",
				AttachTo: "do_sys_open"}, {Type: "kretprobe", LoadFunc: "trace_return",
				AttachTo: "do_sys_open"}}, Outputs: []BPFOutput{{
				Type: "BPF_PERF_OUTPUT", Id: "opensnoop", Key: BPFOutputFormat{
					Name: "hash_key", Type: "u32"}, Format: []BPFOutputFormat{
					{Name: "id", Type: "u64"}, {Name: "fname", Type: "char[255]", IsTag: true}}}}},
		},
	}
	f, err := os.Open("testdata/example_config.yaml")
	if err != nil {
		t.Errorf("Error thrown when opening config file test fixture: %v", err)
		return
	}
	testConfig, err := ParseConfig(f)
	if err != nil {
		t.Errorf("Error thrown when not expected: %v", err)
		return
	}
	fmt.Printf("%v\n%v\n", configFixture, testConfig)
	ignoreTypes := cmpopts.IgnoreTypes(time.Second, gomega.BeFalse(), reflect.TypeOf((int)(0)))
	if !cmp.Equal(configFixture, testConfig, ignoreTypes) {
		t.Errorf("Fixture and expected config do not match")
	}
}
