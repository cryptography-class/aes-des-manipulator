package aes

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

const (
	// KeyLength128 is the length of AES-128 cipher key.
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
	// For now, we stick to AES-128, which is 10 round keys (40 words) + the initial key
	subkeys [4 * (rounds128 + 1)]uint32
}

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

func (a *aes) BlockSize() int {
	//TODO implement me
	panic("implement me")
}

func (a *aes) Encrypt(dst, src []byte) {
	//TODO implement me
	panic("implement me")
}

func (a *aes) Decrypt(dst, src []byte) {
	//TODO implement me
	panic("implement me")
}
