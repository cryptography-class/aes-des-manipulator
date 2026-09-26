package mode

import (
	"bytes"
	"crypto/subtle"
	"fmt"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// cbcEncrypter implements Crypter.
type cbcEncrypter struct {
	cipher block.Cipher
	iv     []byte
}

// NewCBCEncrypter initializes a new CBC Encrypter with the provided
// block cipher.
// It panics when cipher is nil or the length of iv does not match cipher.BlockSize.
//
// It is stateful and not safe for concurrent use.
func NewCBCEncrypter(cipher block.Cipher, iv []byte) Crypter {
	if cipher == nil {
		panic("mode: cipher must not be nil")
	}

	if len(iv) != cipher.BlockSize() {
		panic(fmt.Sprintf("mode: iv length must equal block size, got: %d, want: %d", len(iv), cipher.BlockSize()))
	}

	// create a copy of the iv
	ivCopy := bytes.Clone(iv)

	return &cbcEncrypter{
		cipher: cipher,
		iv:     ivCopy,
	}
}

// BlockSize implements Crypter.
//
// It returns the block size of the underlying cipher in bytes.
func (e *cbcEncrypter) BlockSize() int {
	return e.cipher.BlockSize()
}

// Crypt implements Crypter.
//
// It XORs the plaintext block with the provided iv before encrypting.
// It then uses that encrypted block as the iv for the next one, chaining them together.
func (e *cbcEncrypter) Crypt(dst, src []byte) error {
	blockSize := e.cipher.BlockSize()
	if err := checkBlocks(dst, src, blockSize); err != nil {
		return err
	}

	iv := e.iv
	for i := 0; i < len(src); i += blockSize {
		b := dst[i : i+blockSize]

		subtle.XORBytes(b, iv, src[i:i+blockSize])
		e.cipher.Encrypt(b, b)
		iv = b
	}

	// copy the iv from dst[i : i+blockSize]
	copy(e.iv, iv)

	return nil
}
