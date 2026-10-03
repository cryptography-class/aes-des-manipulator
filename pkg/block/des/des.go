// Package des implements the DES block cipher as specified in FIPS 46-3.
package des

import (
	"encoding/binary"
	"fmt"

	"github.com/cryptography-class/aes-des-manipulator/internal/bits"
	"github.com/cryptography-class/aes-des-manipulator/internal/overlap"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

// blockSize is the block size of DES cipher.
const blockSize = 8

// des implements block.Cipher for the DES cipher.
//
// Spec: https://perso.telecom-paristech.fr/guilley/recherche/cryptoprocesseurs/fips/fips46-3.pdf
type des struct {
	enc [16]uint64
	dec [16]uint64
}

// NewDES initializes a new DES cipher instance that implements block.Cipher.
// It generates 16 subkeys based on the provided key.
// It errors when the length of the key is not 8 bytes or the key is nil.
// DES is a deprecated cipher and should NOT be used in any projects.
// This implementation is for educational purposes.
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
		subkey := bits.Permute((uint64(left)<<28)|uint64(right), 56, pc2Table)
		out.enc[i] = subkey
		out.dec[15-i] = subkey
	}

	return &out, nil
}

// BlockSize implements block.Cipher.
//
// The block size of the DES cipher is 8 bytes.
func (d *des) BlockSize() int {
	return blockSize
}

// crypt applies the DES cipher algorithm onto src in the direction specified by forward.
// It records the result in dst.
// It panics when the size of dst or src is not exactly 8 bytes.
func (d *des) crypt(dst, src []byte, keys *[16]uint64) {
	if len(src) != blockSize {
		panic(fmt.Sprintf("des: src must be 8 bytes long, got: %d", len(src)))
	}

	if len(dst) != blockSize {
		panic(fmt.Sprintf("des: dst must be 8 bytes long, got: %d", len(dst)))
	}

	if overlap.InexactOverlap(dst, src) {
		panic("des: dst and src must not partially overlap")
	}

	// binary.BigEndian.Uint64 and binary.BigEndian.PutUint64 are exceptionally fast
	// at byte to uint64 and vice-versa conversions
	inBits := binary.BigEndian.Uint64(src)
	inBits = permute64(&ipLookup, inBits)

	left := uint32(inBits >> 32)
	right := uint32(inBits & 0xFFFFFFFF)

	for i := range len(keys) {
		temp := d.feistelNetwork(uint64(right), keys[i]) ^ left

		left = right
		right = temp
	}

	// swap the values after the 16th round and run them through ip reverse
	binary.BigEndian.PutUint64(dst, permute64(&ipReverseLookup, uint64(right)<<32|uint64(left)))
}

// Encrypt implements block.Cipher.
//
// Dst and src must overlap entirely or not at all.
// It panics when the size of dst or src is not exactly 8 bytes.
func (d *des) Encrypt(dst, src []byte) {
	d.crypt(dst, src, &d.enc)
}

// Decrypt implements block.Cipher.
//
// Dst and src must overlap entirely or not at all.
// It panics when the size of dst or src is not exactly 8 bytes.
func (d *des) Decrypt(dst, src []byte) {
	d.crypt(dst, src, &d.dec)
}

// feistelNetwork applies the feistel network transformations onto in.
func (d *des) feistelNetwork(in uint64, subkey uint64) uint32 {
	// overlapped in
	x := (in&1)<<33 | in<<1 | in>>31 // b32 | b1...b32 | b1

	// assuming we have
	// b1b2b3b4...b32
	// the E expansion table overlaps 6-bit windows with wraparound:
	// b1b2b3b4 -> b32b1b2b3b4b5
	// b5b6b7b8 -> b4b5b6b7b8b9
	// b9b10b11b12 -> b8b9b10b11b12b13
	// and so on till the end

	// loop unwinding is faster
	var out uint32
	out |= sBoxLookup[0][((x>>28)^(subkey>>42))&0b0111111] // XOR 6 bits of the expansion with 6 bits of the subkey
	out |= sBoxLookup[1][((x>>24)^(subkey>>36))&0b0111111]
	out |= sBoxLookup[2][((x>>20)^(subkey>>30))&0b0111111]
	out |= sBoxLookup[3][((x>>16)^(subkey>>24))&0b0111111]
	out |= sBoxLookup[4][((x>>12)^(subkey>>18))&0b0111111]
	out |= sBoxLookup[5][((x>>8)^(subkey>>12))&0b0111111]
	out |= sBoxLookup[6][((x>>4)^(subkey>>6))&0b0111111]
	out |= sBoxLookup[7][(x^subkey)&0b0111111]

	return out
}
