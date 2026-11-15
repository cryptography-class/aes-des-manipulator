package gcm

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/cryptography-class/aes-des-manipulator/internal/overlap"
	"github.com/cryptography-class/aes-des-manipulator/pkg/aead"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

const (
	// tagSize is the size of the tag produced by GCM.
	tagSize = 16

	// nonceSize is the size of the nonce used by GCM.
	nonceSize = 12

	// blockSize is the size of a single GCM block.
	blockSize = 16

	// maxBlocks is the max number of blocks that GCM can process
	// before returning aead.ErrTooMuchData.
	maxBlocks = 4294967294

	// maxBytes is the max amount of bytes that GCM can process
	// before returning aead.ErrTooMuchData.
	maxBytes = maxBlocks * blockSize // 68,719,476,704 bytes
)

// gcm is the shared base for aead.Sealer and aead.Opener
// implementations of GCM.
type gcm struct {
	cipher block.Cipher
	hash   *ghash
}

// tag produces a tag for written additional data and data.
// It's shared for gcmOpener and gcmSealer.
func (g *gcm) tag(iv []byte) []byte {
	tag := make([]byte, 0, blockSize)
	tag = append(tag, iv...)
	tag = binary.BigEndian.AppendUint32(tag, 1)
	g.cipher.Encrypt(tag, tag)

	sum := g.hash.sum()
	subtle.XORBytes(
		tag,
		tag,
		sum[:],
	)

	return tag
}

// NonceSize implements aead.Sealer and aead.Opener.
func (g *gcm) NonceSize() int {
	return nonceSize
}

// Overhead implements aead.Sealer and aead.Opener.
func (g *gcm) Overhead() int {
	return tagSize
}

// checkGCM checks that the cipher and iv are appropriate for GCM.
func checkGCM(cipher block.Cipher, iv []byte) {
	if cipher == nil {
		panic("gcm: cipher must not be nil")
	}

	if cipher.BlockSize() != blockSize {
		panic(fmt.Sprintf("gcm: cipher's block size must equal %d, got %d", blockSize, cipher.BlockSize()))
	}

	if len(iv) != nonceSize {
		panic(fmt.Sprintf("gcm: iv must have length %d, got %d", nonceSize, len(iv)))
	}
}

// checkOverlap checks whether dst and src have an equal length
// and overlap entirely or not at all.
func checkOverlap(dst, src []byte) error {
	if len(dst) != len(src) {
		return aead.ErrLengthMismatch
	}

	if overlap.InexactOverlap(dst, src) {
		return aead.ErrInexactOverlap
	}

	return nil
}
