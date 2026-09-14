package testutil

import (
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
