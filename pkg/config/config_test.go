package config

import (
	"errors"
	"strings"
	"testing"
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
		t.Errorf("Faulty reader did not throw error!")
	}
}

// Confirm invalid YAML will error out
func TestParseConfigFailsOnBadYAML(t *testing.T) {
	badYAML := strings.NewReader("This isn't valid YAML")
	_, err := ParseConfig(badYAML)
	if err == nil {
		t.Errorf("Invalid input YAML did not throw error!")
	}
}
