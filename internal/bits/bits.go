// Package bits implements functions for bitwise operations.
package bits

// unsigned represents all unsigned integers.
type unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// GetBit returns a bit at position from an integer that has length bits.
// Indices start with 1 going from left to right.
// position should be in [1, length]. length should be non-negative.
func GetBit[T unsigned](x T, length int, position int) T {
	shift := length - position
	return (x >> shift) & 1
}

// Permute applies the permutation to an integer that has length bits.
// Bits are right-aligned. If len(permutation) exceeds T's bit width - the output is silently truncated.
// length should be non-negative.
func Permute[T unsigned](x T, length int, permutation []int) T {
	var out T
	for _, position := range permutation {
		out = (out << 1) | GetBit(x, length, position)
		// bits are right-aligned
	}

	return out
}

// LeftRotate cyclically rotates an integer that has length bits by shift bits.
// x is masked to its low length bits first; any higher bits are silently discarded.
// length should be non-negative.
func LeftRotate[T unsigned](x T, length int, shift int) T {
	mask := T(1)<<length - 1
	x &= mask
	return ((x << shift) | (x >> (length - shift))) & mask
}
