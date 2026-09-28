package mode

import (
	"bytes"
	"crypto/subtle"
	"fmt"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// TODO: MAYBE PRECOMPUTE FOR LARGE BLOCKS AFTER PROFILING

// ctrCrypter implements Crypter.
//
// It serves as both the Encrypter and Decrypter.
type ctrCrypter struct {
	cipher    block.Cipher
	counter   []byte
	keystream []byte
	// bytes of keystream already consumed
	// when keystreamIndex == blockSize -> Encrypt counter
	keystreamIndex int
}

// NewCTREncrypter initializes a new CTR Encrypter with the provided
// block cipher.
// It panics when cipher is nil or the length of iv does not match cipher.BlockSize.
func NewCTREncrypter(cipher block.Cipher, iv []byte) Crypter {
	return newCTR(cipher, iv)
}

// NewCTRDecrypter initializes a new CTR Decrypter with the provided
// block cipher.
// It panics when cipher is nil or the length of iv does not match cipher.BlockSize.
func NewCTRDecrypter(cipher block.Cipher, iv []byte) Crypter {
	return newCTR(cipher, iv)
}

// newCTR is an initializer for NewCTREncrypter and NewCTRDecrypter.
func newCTR(cipher block.Cipher, iv []byte) *ctrCrypter {
	if cipher == nil {
		panic("mode: cipher must not be nil")
	}

	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		panic(fmt.Sprintf("mode: iv length must equal block size, got: %d, want: %d", len(iv), blockSize))
	}

	return &ctrCrypter{
		cipher:         cipher,
		counter:        bytes.Clone(iv),
		keystream:      make([]byte, blockSize),
		keystreamIndex: blockSize,
	}
}

// BlockSize implements Crypter.
//
// It returns the block size of the underlying cipher in bytes.
func (e *ctrCrypter) BlockSize() int {
	return e.cipher.BlockSize()
}

// Crypt implements Crypter.
//
// It turns a provided block.Cipher into a stream cipher.
func (e *ctrCrypter) Crypt(dst, src []byte) error {
	if err := checkOverlap(dst, src); err != nil {
		return err
	}

	blockSize := e.cipher.BlockSize()
	idx := 0

	for idx < len(src) {
		if e.keystreamIndex == blockSize {
			e.cipher.Encrypt(e.keystream, e.counter)
			e.incrementCounter()
			e.keystreamIndex = 0
		}

		n := min(blockSize-e.keystreamIndex, len(src)-idx)
		subtle.XORBytes(
			dst[idx:idx+n],
			src[idx:idx+n],
			e.keystream[e.keystreamIndex:e.keystreamIndex+n],
		)

		e.keystreamIndex += n
		idx += n
	}

	return nil
}

// incrementCounter treats counter as a big-endian and increments it.
func (e *ctrCrypter) incrementCounter() {
	for i := len(e.counter) - 1; i >= 0; i-- {
		e.counter[i]++
		if e.counter[i] != 0 {
			return
		}
	}
}
