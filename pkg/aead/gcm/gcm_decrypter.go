package gcm

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"

	"github.com/cryptography-class/aes-des-manipulator/internal/counter"
	"github.com/cryptography-class/aes-des-manipulator/pkg/aead"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// gcmDecrypter implements aead.Decrypter for GCM.
type gcmDecrypter struct {
	cipher block.Cipher

	// counter is IV || 2, only the last 32 bits are incremented.
	counter []byte

	keystream      []byte
	keystreamIndex int

	// pos is the number of bytes decrypted so far, counted from
	// the start of the ciphertext (including the At offset).
	// GCM supports at most 64GiB of data.
	pos uint64
}

// newGCMDecrypter intializes a new gcmDecrypter to use after gcmOpener.Verify.
func newGCMDecrypter(cipher block.Cipher, iv []byte) *gcmDecrypter {
	ctr := make([]byte, 0, blockSize)
	ctr = append(ctr, iv...)
	ctr = binary.BigEndian.AppendUint32(ctr, 2)

	return &gcmDecrypter{
		cipher:         cipher,
		counter:        ctr,
		keystream:      make([]byte, blockSize),
		keystreamIndex: blockSize,
	}
}

// Decrypt implements aead.Decrypter.
func (g *gcmDecrypter) Decrypt(dst, src []byte) error {
	if err := checkOverlap(dst, src); err != nil {
		return err
	}

	// reject src that would overflow the 64GiB boundary
	if uint64(len(src)) > maxBytes-g.pos {
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

		g.keystreamIndex += n
		idx += n
	}

	g.pos += uint64(len(src))
	return nil
}

// At implements aead.Decrypter.
func (g *gcmDecrypter) At(blocks uint64) (aead.Decrypter, error) {
	if blocks >= maxBlocks {
		return nil, aead.ErrTooMuchData
	}

	ctr := bytes.Clone(g.counter[:12])
	ctr = binary.BigEndian.AppendUint32(ctr, 2)
	counter.Increment(ctr[12:], blocks)

	return &gcmDecrypter{
		cipher:         g.cipher,
		counter:        ctr,
		keystream:      make([]byte, blockSize),
		keystreamIndex: blockSize,
		pos:            blocks * blockSize,
	}, nil
}
