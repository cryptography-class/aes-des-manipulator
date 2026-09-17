// Package des implements the DES block cipher as specified in FIPS 46-3.
package des

import (
	"encoding/binary"
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

	// binary.BigEndian.Uint64 and binary.BigEndian.PutUint64 are exceptionally fast
	// at byte to uint64 and vice-versa conversions
	keyBits := binary.BigEndian.Uint64(key)
	keyBits = bits.Permute(keyBits, 64, pc1Table)

	// we do not verify the parity bits

	left := uint32(keyBits >> 28)
	right := uint32(keyBits & 0x0FFFFFFF)

	var out des
	for i, shift := range shiftSchedule {
		left = bits.LeftRotate(left, 28, shift)
		right = bits.LeftRotate(right, 28, shift)

		// concatenate the values and run them through pc2
		out.subkeys[i] = bits.Permute((uint64(left)<<28)|uint64(right), 56, pc2Table)
	}

	return &out, nil
}

// BlockSize implements block.Cipher.
func (d *des) BlockSize() int {
	return blockSize
}

func (d *des) validateBlocks(dst, src []byte) {
	if len(src) != blockSize {
		panic(fmt.Sprintf("des: src must be 8 bytes long, got: %d", len(src)))
	}

	if len(dst) != blockSize {
		panic(fmt.Sprintf("des: dst must be 8 bytes long, got: %d", len(dst)))
	}
}

func (d *des) crypt(dst, src []byte, forward bool) {
	d.validateBlocks(dst, src)

	// binary.BigEndian.Uint64 and binary.BigEndian.PutUint64 are exceptionally fast
	// at byte to uint64 and vice-versa conversions
	inBits := binary.BigEndian.Uint64(src)
	inBits = bits.Permute(inBits, 64, ipTable)

	left := uint32(inBits >> 32)
	right := uint32(inBits & 0xFFFFFFFF)

	for i := range len(d.subkeys) {
		if !forward {
			i = len(d.subkeys) - 1 - i
		}
		subkey := d.subkeys[i]

		temp := d.processFeistelNetwork(uint64(right), subkey) ^ left

		left = right
		right = temp
	}

	// swap the values after the 16th round and run them through ip reverse
	binary.BigEndian.PutUint64(dst, bits.Permute(uint64(right)<<32|uint64(left), 64, ipReverseTable))
}

// Encrypt implements block.Cipher.
func (d *des) Encrypt(dst, src []byte) {
	d.crypt(dst, src, true)
}

// Decrypt implements block.Cipher.
func (d *des) Decrypt(dst, src []byte) {
	d.crypt(dst, src, false)
}

func (d *des) processFeistelNetwork(in uint64, subkey uint64) uint32 {
	out := bits.Permute(in, 32, eTable) ^ subkey
	out = d.processSBoxes(out)

	return uint32(bits.Permute(out, 32, pTable))
}

// TODO: REPLACE WITH A PRECOMUPTED MAP
func (d *des) processSBoxes(in uint64) uint64 {
	var out uint64
	for i, box := range sBoxes {
		temp := in >> (48 - 6*(i+1)) & 0b111111

		row := (bits.GetBit[uint64](temp, 6, 1) << 1) | bits.GetBit[uint64](temp, 6, 6)
		column := (temp >> 1) & 0b1111

		// append 4 bits into out based on row and column
		out = out<<4 | box[row*sBoxRowSize+column]
	}

	return out
}
