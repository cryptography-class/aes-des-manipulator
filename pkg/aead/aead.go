package aead

// Sealer is the encryption interface implemented by AEADs.
type Sealer interface {
	// WriteAD appends additional data that will be authenticated.
	// It panics if used after Write.
	WriteAD(data []byte)

	// Write encrypts src, writes the result into dst and appends it
	// to a running hashsum.
	// Dst and src must overlap entirely or not at all, and both must be
	// the same length.
	// It returns ErrTooMuchData if the size of the total encrypted data
	// overflows a specified boundary.
	// It panics if used after Tag.
	Write(dst, src []byte) error

	// Tag produces a tag for the additional data and ciphertext.
	// Sealer should be discarded after calling Tag.
	// It panics when called multiple times.
	Tag() []byte

	// NonceSize returns the size of the nonce.
	NonceSize() int

	// Overhead returns the size of the tag produced by AEAD.
	Overhead() int
}

// Opener is the verification interface implemented by AEADs.
type Opener interface {
	// WriteAD appends additional data that will be authenticated.
	// It panics if used after Write.
	WriteAD(data []byte)

	// Write appends ciphertext to a running hashsum.
	// It returns ErrTooMuchData if the size of the total encrypted data
	// overflows a specified boundary.
	// It panics if used after Verify.
	Write(ciphertext []byte) error

	// Verify checks that the provided tag is valid for written
	// additional data and ciphertext.
	// It returns a Decrypter used to decrypt the data if the tag matches the data.
	// It returns ErrInvalidAuthentication when the tag does not match the data.
	// Opener should be discarded after calling Verify.
	// It panics when called multiple times.
	Verify(tag []byte) (Decrypter, error)

	// NonceSize returns the size of the nonce.
	NonceSize() int

	// Overhead returns the size of the tag produced by AEAD.
	Overhead() int
}

// Decrypter is the decryption interface implemented by AEADs.
// It should only be used on the same data Opener verified.
type Decrypter interface {
	// Decrypt decrypts src into dst.
	// Dst and src must overlap entirely or not at all, and both must be
	// the same length.
	// It returns ErrTooMuchData if the size of the total decrypted data
	// overflows a specified boundary.
	Decrypt(dst, src []byte) error

	// At returns an instance of the Decrypter shifted by a blocks offset
	// from the beginning.
	// It returns ErrTooMuchData if the shift would overflow
	// a specified boundary.
	At(blocks uint64) (Decrypter, error)
}
