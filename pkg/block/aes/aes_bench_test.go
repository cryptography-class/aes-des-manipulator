package aes

import (
	std "crypto/aes"
	"fmt"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
)

type Implementation struct {
	name string
	new  func(key []byte) (block.Cipher, error)
}

var Implementations = []Implementation{
	{
		name: "crypto",
		new:  func(key []byte) (block.Cipher, error) { return std.NewCipher(key) },
	},
	{
		name: "custom",
		new:  func(key []byte) (block.Cipher, error) { return NewAES(key) },
	},
}

var BenchVectors = []struct {
	name       string
	keyLen     int
	ciphertext []byte
}{
	{
		name:       "AES-128",
		keyLen:     16,
		ciphertext: []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
	},
	{
		name:       "AES-192",
		keyLen:     24,
		ciphertext: []byte{0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91},
	},
	{
		name:       "AES-256",
		keyLen:     32,
		ciphertext: []byte{0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89},
	},
}

var BenchPlaintext = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

func BenchKey(n int) []byte {
	key := make([]byte, n)
	for i := range key {
		key[i] = byte(i)
	}

	return key
}

func BenchmarkNewCipher(b *testing.B) {
	for _, v := range BenchVectors {
		key := BenchKey(v.keyLen)
		for _, im := range Implementations {
			b.Run(fmt.Sprintf("%s/implementation=%s", v.name, im.name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := im.new(key); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for _, v := range BenchVectors {
		key := BenchKey(v.keyLen)
		for _, im := range Implementations {
			b.Run(fmt.Sprintf("%s/implementation=%s", v.name, im.name), func(b *testing.B) {
				c, err := im.new(key)
				if err != nil {
					b.Fatal(err)
				}
				dst := make([]byte, BlockSize)

				b.SetBytes(BlockSize)
				b.ReportAllocs()
				for b.Loop() {
					c.Encrypt(dst, BenchPlaintext)
				}
			})
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, v := range BenchVectors {
		key := BenchKey(v.keyLen)
		for _, im := range Implementations {
			b.Run(fmt.Sprintf("%s/implementation=%s", v.name, im.name), func(b *testing.B) {
				c, err := im.new(key)
				if err != nil {
					b.Fatal(err)
				}
				dst := make([]byte, BlockSize)

				b.SetBytes(BlockSize)
				b.ReportAllocs()
				for b.Loop() {
					c.Decrypt(dst, v.ciphertext)
				}
			})
		}
	}
}
