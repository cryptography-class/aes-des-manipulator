// Package mode defines different crypting modes.
package mode

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
