package gcm

import (
	"bytes"
	"crypto/subtle"

	"github.com/cryptography-class/aes-des-manipulator/pkg/aead"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// gcmOpener implements aead.Opener for GCM.
type gcmOpener struct {
	gcm

	iv []byte
}

// NewGCMOpener initializes a new GCM aead.Opener with the provided cipher and iv.
// It panics when cipher is nil, its block size is not exactly 16 bytes
// or iv is not exactly 12 bytes.
func NewGCMOpener(cipher block.Cipher, iv []byte) aead.Opener {
	checkGCM(cipher, iv)

	h := make([]byte, blockSize)
	cipher.Encrypt(h, h)

	return &gcmOpener{
		cipher: cipher,
		hash:   newGhash([16]byte(h)),
		iv:     bytes.Clone(iv),
	}
}

// WriteAD implements aead.Opener.
func (g *gcmOpener) WriteAD(data []byte) {
	g.hash.writeAAD(data)
}

// Write implements aead.Opener.
func (g *gcmOpener) Write(ciphertext []byte) error {
	if uint64(len(ciphertext)) > maxBytes-g.hash.ciphertextLength {
		return aead.ErrTooMuchData
	}

	g.hash.writeCiphertext(ciphertext)
	return nil
}

// Verify implements aead.Opener.
func (g *gcmOpener) Verify(tag []byte) (aead.Decrypter, error) {
	if len(tag) != tagSize {
		return nil, aead.ErrInvalidAuthentication
	}

	got := g.tag(g.iv)
	if subtle.ConstantTimeCompare(got, tag) != 1 {
		return nil, aead.ErrInvalidAuthentication
	}

	return newGCMDecrypter(g.cipher, g.iv), nil
}
