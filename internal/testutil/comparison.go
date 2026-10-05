package testutil

import (
	"bytes"
	"reflect"
	"testing"
)

// AssertEqual checks got against want for equality.
func AssertEqual[T comparable](t *testing.T, got T, want T) {
	t.Helper()

	if got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
}

// AssertDeepEqual checks got against want for deep equality.
func AssertDeepEqual[T any](t *testing.T, got T, want T) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
}

// AssertBytesEqual checks got againt want for bytes equality.
func AssertBytesEqual(t *testing.T, got []byte, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
}
