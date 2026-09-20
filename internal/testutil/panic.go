package testutil

import (
	"errors"
	"testing"
)

// AssertPanic checks recover against whether a panic was expected.
// Should run in a defer statement.
func AssertPanic(t *testing.T, r any, wantPanic bool) {
	t.Helper()

	if wantPanic && r == nil {
		t.Errorf("expected panic, got none")
	}

	if !wantPanic && r != nil {
		t.Errorf("unexpected panic: %v", r)
	}
}

// AssertNilError checks got against whether an error was expected.
func AssertNilError(t *testing.T, got error, wantError bool) {
	t.Helper()

	if wantError && got == nil {
		t.Errorf("expected error, got none")
	}

	if !wantError && got != nil {
		t.Errorf("unexpected error: %v", got)
	}
}

// AssertError checks got against want error using errors.Is.
func AssertError(t *testing.T, got error, want error) {
	t.Helper()

	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
