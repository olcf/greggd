package config

import (
	"errors"
	"testing"
)

func TestParseConfig(t *testing.T) {
}

// Define a new type that will match the io.Reader interface
type readThrowErr int

func (readThrowErr) Read(b []byte) (n int, err error) {
	return 0, errors.New("Intentional Err")
}

func TestParseConfigFailsOnBadReader(t *testing.T) {
	// Make fake reader that will throw Err when Read is called
	var fakeReader readThrowErr
	fakeReader = 0
	_, err := ParseConfig(fakeReader)
	if err == nil {
		t.Errorf("Faulty reader did not throw error!")
	}
}
