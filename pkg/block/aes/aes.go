package aes

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/cryptography-class/aes-des-manipulator/internal/overlap"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

const (
	// BlockSize is the block size of AES cipher in bytes.
	BlockSize = 16

	// KeyLength128 is the length of AES-128 cipher key in bytes.
	KeyLength128 = 16
)

const (
	// keyWords128 is the length of AES-128 cipher key in 32-bit words.
	keyWords128 = KeyLength128 / 4
	// rounds128 is the amount of rounds in AES-128.
	rounds128 = 10
)

// aes implements block.Cipher.
//
// Spec: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
type aes struct {
	// For now, we stick to AES-128, which is 10 round keys (40 words) + the initial key (4 words)
	subkeys [4 * (rounds128 + 1)]uint32
}

// NewAES initializes a new AES cipher instance that implements block.Cipher.
//
// It produces only AES-128 and errors when the length of the key is not 16 bytes.
//
// TODO: Implement AES-192 and AES-256.
func NewAES(key []byte) (block.Cipher, error) {
	keyLength := len(key)
	switch keyLength {
	case KeyLength128:
		// TODO: add rounds, keyWords, etc selection based on AES-128, AES-192 and AES-256
		// For now, we stick to AES-128

	default:
		return nil, fmt.Errorf("aes: key must be %d bytes long, got: %d", KeyLength128, keyLength)
	}

	words := make([]uint32, 4*(rounds128+1))
	for i := range keyWords128 {
		words[i] = binary.BigEndian.Uint32(key[i*4:])
	}

	for i := keyWords128; i < len(words); i++ {
		temp := words[i-1]
		if i%keyWords128 == 0 {
			temp = subWord(bits.RotateLeft32(temp, 8)) ^ rcon[(i/keyWords128)-1]
		}

		words[i] = words[i-keyWords128] ^ temp
	}

	subkeys := [4 * (rounds128 + 1)]uint32(words)
	return &aes{
		subkeys: subkeys,
	}, nil
}

// BlockSize implements block.Cipher.
//
// The block size of the AES cipher is 16 bytes.
func (a *aes) BlockSize() int {
	return BlockSize
}

// Encrypt implements block.Cipher.
//
// Dst and src must overlap entirely or not at all.
// It panics when the size of dst or src is not exactly 16 bytes.
func (a *aes) Encrypt(dst, src []byte) {
	if len(src) != BlockSize {
		panic(fmt.Sprintf("aes: src must be 16 bytes long, got: %d", len(src)))
	}

	if len(dst) != BlockSize {
		panic(fmt.Sprintf("aes: dst must be 16 bytes long, got: %d", len(dst)))
	}

	if overlap.InexactOverlap(dst, src) {
		panic("aes: dst and src must not partially overlap")
	}

	// state is the initial state matrix after the 0th key is applied
	// stored column by column
	state := [4]uint32{
		binary.BigEndian.Uint32(src[0:]) ^ a.subkeys[0],
		binary.BigEndian.Uint32(src[4:]) ^ a.subkeys[1],
		binary.BigEndian.Uint32(src[8:]) ^ a.subkeys[2],
		binary.BigEndian.Uint32(src[12:]) ^ a.subkeys[3],
	}

	for i := range rounds128 - 1 {
		state[0] = subWord(state[0])
		state[1] = subWord(state[1])
		state[2] = subWord(state[2])
		state[3] = subWord(state[3])

		// Columns after ShiftRows:
		// 0 -> a0 b1 c2 d3
		// 1 -> a1 b2 c3 d0
		// 2 -> a2 b3 c0 d1
		// 3 -> a3 b0 c1 d2
		//
		// The rule of thumb is
		// a = 0xff000000 b = 0x00ff0000 c = 0x0000ff00 d = 0x000000ff
		// only indices change

		s := state // copy of the state
		state[0] = (s[0] & 0xff000000) | (s[1] & 0x00ff0000) |
			(s[2] & 0x0000ff00) | (s[3] & 0x000000ff)
		state[1] = (s[1] & 0xff000000) | (s[2] & 0x00ff0000) |
			(s[3] & 0x0000ff00) | (s[0] & 0x000000ff)
		state[2] = (s[2] & 0xff000000) | (s[3] & 0x00ff0000) |
			(s[0] & 0x0000ff00) | (s[1] & 0x000000ff)
		state[3] = (s[3] & 0xff000000) | (s[0] & 0x00ff0000) |
			(s[1] & 0x0000ff00) | (s[2] & 0x000000ff)

		// mix columns and xor with the key
		state[0] = mixColumn(state[0]) ^ a.subkeys[4*(i+1)]
		state[1] = mixColumn(state[1]) ^ a.subkeys[4*(i+1)+1]
		state[2] = mixColumn(state[2]) ^ a.subkeys[4*(i+1)+2]
		state[3] = mixColumn(state[3]) ^ a.subkeys[4*(i+1)+3]
	}

	// final round
	state[0] = subWord(state[0])
	state[1] = subWord(state[1])
	state[2] = subWord(state[2])
	state[3] = subWord(state[3])

	// shift rows and xor with the last key
	s := state
	state[0] = ((s[0] & 0xff000000) | (s[1] & 0x00ff0000) |
		(s[2] & 0x0000ff00) | (s[3] & 0x000000ff)) ^ a.subkeys[rounds128*4]
	state[1] = ((s[1] & 0xff000000) | (s[2] & 0x00ff0000) |
		(s[3] & 0x0000ff00) | (s[0] & 0x000000ff)) ^ a.subkeys[rounds128*4+1]
	state[2] = ((s[2] & 0xff000000) | (s[3] & 0x00ff0000) |
		(s[0] & 0x0000ff00) | (s[1] & 0x000000ff)) ^ a.subkeys[rounds128*4+2]
	state[3] = ((s[3] & 0xff000000) | (s[0] & 0x00ff0000) |
		(s[1] & 0x0000ff00) | (s[2] & 0x000000ff)) ^ a.subkeys[rounds128*4+3]

	// store the result in dst
	binary.BigEndian.PutUint32(dst[0:], state[0])
	binary.BigEndian.PutUint32(dst[4:], state[1])
	binary.BigEndian.PutUint32(dst[8:], state[2])
	binary.BigEndian.PutUint32(dst[12:], state[3])
}

// Decrypt implements block.Cipher.
//
// Dst and src must overlap entirely or not at all.
// It panics when the size of dst or src is not exactly 16 bytes.
func (a *aes) Decrypt(dst, src []byte) {
	//TODO implement me
	panic("implement me")
}
