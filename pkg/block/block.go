// Package block defines the contract for block ciphers.
package block

// Cipher is the interface implemented by block cipher algorithms.
type Cipher interface {
	// BlockSize returns the cipher's block size in bytes.
	BlockSize() int

	// Encrypt encrypts src into dst using the cipher's algorithm.
	// Dst and src must overlap entirely or not at all,
	// and both must be the same size and exactly BlockSize() bytes long,
	// or Encrypt panics.
	Encrypt(dst, src []byte)

	// Decrypt decrypts src into dst using the cipher's algorithm.
	// Dst and src must overlap entirely or not at all,
	// and both must be the same size and exactly BlockSize() bytes long,
	// or Decrypt panics.
	Decrypt(dst, src []byte)
}
