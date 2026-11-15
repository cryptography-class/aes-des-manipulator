package gcm

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/cryptography-class/aes-des-manipulator/internal/counter"
	"github.com/cryptography-class/aes-des-manipulator/pkg/aead"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// gcmSealer implements aead.Sealer for GCM.
type gcmSealer struct {
	gcm

	// counter is IV || 2, only the last 32 bits are incremented.
	counter []byte

	keystream      []byte
	keystreamIndex int
}

// NewGCMSealer initializes a new GCM aead.Sealer with the provided cipher and iv.
// It panics when cipher is nil, its block size is not exactly 16 bytes
// or iv is not exactly 12 bytes.
func NewGCMSealer(cipher block.Cipher, iv []byte) aead.Sealer {
	checkGCM(cipher, iv)

	h := make([]byte, blockSize)
	cipher.Encrypt(h, h)

	ctr := make([]byte, 0, blockSize)
	ctr = append(ctr, iv...)
	ctr = binary.BigEndian.AppendUint32(ctr, 2)

	return &gcmSealer{
		cipher:         cipher,
		hash:           newGhash([16]byte(h)),
		counter:        ctr,
		keystream:      make([]byte, blockSize),
		keystreamIndex: blockSize,
	}
}

// WriteAD implements aead.Sealer.
func (g *gcmSealer) WriteAD(data []byte) {
	g.hash.writeAAD(data)
}

// Write implements aead.Sealer.
func (g *gcmSealer) Write(dst, src []byte) error {
	if err := checkOverlap(dst, src); err != nil {
		return err
	}

	// reject src that would overflow the 64GiB boundary
	if uint64(len(src)) > maxBytes-g.hash.ciphertextLength {
		return aead.ErrTooMuchData
	}

	idx := 0
	for idx < len(src) {
		if g.keystreamIndex == blockSize {
			g.cipher.Encrypt(g.keystream, g.counter)

			// gcm increments just the last 4 bytes of the counter
			counter.Increment(g.counter[12:], 1)
			g.keystreamIndex = 0
		}

		n := min(blockSize-g.keystreamIndex, len(src)-idx)
		subtle.XORBytes(
			dst[idx:idx+n],
			src[idx:idx+n],
			g.keystream[g.keystreamIndex:g.keystreamIndex+n],
		)
		g.hash.writeCiphertext(dst[idx : idx+n])

		g.keystreamIndex += n
		idx += n
	}

	return nil
}

// Tag implements aead.Sealer.
func (g *gcmSealer) Tag() []byte {
	// iv is the first 12 bytes of the counter
	return g.tag(g.counter[:12])
}
