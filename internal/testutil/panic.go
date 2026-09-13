package testutil

import "testing"

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
