package mode

import (
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// ecbEncrypter implements Crypter.
type ecbEncrypter struct {
	cipher block.Cipher
}

// NewECBEncrypter initializes a new ECB Encrypter with the provided
// block cipher.
// It encrypts blocks one after another, preserving patterns, which
// makes it cryptographically weak.
// It panics when cipher is null.
func NewECBEncrypter(cipher block.Cipher) Crypter {
	if cipher == nil {
		panic("mode: cipher must not be nil")
	}

	return &ecbEncrypter{
		cipher: cipher,
	}
}

// BlockSize implements Crypter.
//
// It returns the block size of the underlying cipher in bytes.
func (e *ecbEncrypter) BlockSize() int {
	return e.cipher.BlockSize()
}

// Crypt implements Crypter.
//
// It encrypts each block of src independently using the underlying
// cipher and writes the result into dst.
func (e *ecbEncrypter) Crypt(dst, src []byte) error {
	blockSize := e.cipher.BlockSize()
	if err := checkBlocks(dst, src, blockSize); err != nil {
		return err
	}

	for i := 0; i < len(src); i += blockSize {
		e.cipher.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}

	return nil
}

// ecbDecrypter implements Crypter.
type ecbDecrypter struct {
	cipher block.Cipher
}

// NewECBDecrypter initializes a new ECB Decrypter with the provided
// block cipher.
// It decrypts blocks one after another.
// It panics when cipher is null.
func NewECBDecrypter(cipher block.Cipher) Crypter {
	if cipher == nil {
		panic("mode: cipher must not be nil")
	}

	return &ecbDecrypter{
		cipher: cipher,
	}
}

// BlockSize implements Crypter.
//
// It returns the block size of the underlying cipher in bytes.
func (e *ecbDecrypter) BlockSize() int {
	return e.cipher.BlockSize()
}

// Crypt implements Crypter.
//
// It decrypts each block of src independently using the underlying
// cipher and writes the result into dst.
func (e *ecbDecrypter) Crypt(dst, src []byte) error {
	blockSize := e.cipher.BlockSize()
	if err := checkBlocks(dst, src, blockSize); err != nil {
		return err
	}

	for i := 0; i < len(src); i += blockSize {
		e.cipher.Decrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}

	return nil
}
