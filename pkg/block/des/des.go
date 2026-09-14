// Package des implements the DES block cipher as specified in FIPS 46-3.
package des

import (
	"fmt"

	"github.com/cryptography-class/aes-des-manipulator/internal/bits"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// blockSize is the block size of des cipher.
const blockSize = 8

// des implements block.Cipher for the DES cipher.
// Spec: https://perso.telecom-paristech.fr/guilley/recherche/cryptoprocesseurs/fips/fips46-3.pdf
type des struct {
	subkeys [16]uint64
}

// NewDES initializes a new des cipher instance that implements block.Cipher.
// It generates 16 subkeys based on the provided key.
// It errors when the length of the key is not 8 bytes or the key is nil.
func NewDES(key []byte) (block.Cipher, error) {
	if key == nil {
		return nil, fmt.Errorf("des: key must not be nil")
	}

	if len(key) != 8 {
		return nil, fmt.Errorf("des: key must be 8 bytes long, got: %d", len(key))
	}

	var keyBits uint64
	for _, b := range key {
		keyBits = (keyBits << 8) | uint64(b)
	}

	// we do not verify the parity bits

	pc1 := bits.Permute(keyBits, 64, pc1Table)
	left := uint32(pc1 >> 28)
	right := uint32(pc1 & 0x0FFFFFFF)

	var out des
	for i, shift := range shiftSchedule {
		left = bits.LeftRotate(left, 28, shift)
		right = bits.LeftRotate(right, 28, shift)

		full := (uint64(left) << 28) | uint64(right)
		out.subkeys[i] = bits.Permute(full, 56, pc2Table)
	}

	return &out, nil
}

// BlockSize implements block.Cipher.
func (d *des) BlockSize() int {
	return blockSize
}

// Encrypt implements block.Cipher.
func (d *des) Encrypt(dst, src []byte) {
	panic("NOT IMPLEMENTED")
}

// Decrypt implements block.Cipher.
func (d *des) Decrypt(dst, src []byte) {
	panic("NOT IMPLEMENTED")
}
