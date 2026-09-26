package mode

import "errors"

var (
	// ErrLengthMismatch is returned when dst and src have different lengths.
	ErrLengthMismatch = errors.New("mode: dst and src length mismatch")

	// ErrNotFullBlocks is returned when the length of src is not a multiple of block size
	// and requires padding.
	ErrNotFullBlocks = errors.New("mode: input is not a multiple of the block size")

	// ErrInexactOverlap is returned when dst and src partially overlap.
	ErrInexactOverlap = errors.New("mode: dst and src partially overlap")
)
