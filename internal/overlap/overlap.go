// Package overlap reports whether slices share memory.
package overlap

import "unsafe"

// AnyOverlap reports whether x and y share any memory.
func AnyOverlap(x []byte, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// InexactOverlap reports whether x and y share memory
// at anything other than the starting address.
func InexactOverlap(x []byte, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}

	return AnyOverlap(x, y)
}
