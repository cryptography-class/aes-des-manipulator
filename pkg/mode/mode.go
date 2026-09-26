// Package mode defines different crypting modes.
package mode

import "github.com/cryptography-class/aes-des-manipulator/internal/overlap"

// Crypter is the interface implemented by crypting modes.
type Crypter interface {
	// BlockSize returns the block size of the underlying cipher in bytes.
	BlockSize() int

	// Crypt applies the mode's encryption or decryption algorithm to src
	// and writes the result into dst.
	// Dst and src must overlap entirely or not at all, and both must be
	// the same length, a non-zero multiple of BlockSize bytes.
	// It should error where the underlying cipher would panic.
	Crypt(dst, src []byte) error
}

// checkBlocks checks whether dst and src have the same length,
// which is a multiple of blockSize, and overlap entirely or not at all.
func checkBlocks(dst []byte, src []byte, blockSize int) error {
	if len(dst) != len(src) {
		return ErrLengthMismatch
	}

	if len(src)%blockSize != 0 {
		return ErrNotFullBlocks
	}

	if overlap.InexactOverlap(dst, src) {
		return ErrInexactOverlap
	}

	return nil
}
