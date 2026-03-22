package runtimeenv

import "testing"

func TestBinaryVersion_nonEmpty(t *testing.T) {
	v := BinaryVersion()
	if v == "" {
		t.Fatal()
	}
}
