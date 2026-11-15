package gcm

import (
	"embed"
	"fmt"
	"strconv"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/aes"
)

type operation uint8

const (
	encrypt operation = iota
	decrypt
)

//go:embed testdata/gcm/*.rsp
var gcmTestDataFS embed.FS

const (
	gcmMatch = "testdata/gcm/*.rsp"

	encryptSection = "ENCRYPT"
	decryptSection = "DECRYPT"
)

// gcmTestCase is a single test case for AES-GCM.
type gcmTestCase struct {
	name       string
	op         operation
	key        []byte
	iv         []byte
	ciphertext []byte
	plaintext  []byte
	dst        []byte
	aad        []byte
	tag        []byte
	pass       bool
}

func parseGCMKAT(r testutil.Record) (gcmTestCase, error) {
	var zero gcmTestCase
	key, err := r.Hex("KEY", aes.KeyLength128, aes.KeyLength192, aes.KeyLength256)
	if err != nil {
		return zero, err
	}

	iv, err := r.Hex("IV", NonceSize)
	if err != nil {
		return zero, err
	}

	ciphertext, err := r.Hex("CT")
	if err != nil {
		return zero, err
	}

	aad, err := r.Hex("AAD")
	if err != nil {
		return zero, err
	}

	tag, err := r.Hex("TAG", TagSize)
	if err != nil {
		return zero, err
	}

	pass := false
	if r.Section == decryptSection {
		pass, err = strconv.ParseBool(r.Fields["PASS"])
		if err != nil {
			return zero, err
		}
	}

	var plaintext []byte
	if pass || r.Section == encryptSection {
		plaintext, err = r.Hex("PT")
		if err != nil {
			return zero, err
		}
	}

	var op operation
	switch r.Section {
	case encryptSection:
		op = encrypt

	case decryptSection:
		op = decrypt

	default:
		return zero, fmt.Errorf("unknown section %q", r.Section)
	}

	return gcmTestCase{
		name:       r.Name,
		op:         op,
		key:        key,
		iv:         iv,
		ciphertext: ciphertext,
		plaintext:  plaintext,
		dst:        nil,
		aad:        aad,
		tag:        tag,
		pass:       pass,
	}, nil
}

func TestGCMKAT(t *testing.T) {
	folder := &testutil.TestFolder{
		FS:    &gcmTestDataFS,
		Match: gcmMatch,
	}

	for _, tt := range testutil.ParseTests(t, folder, parseGCMKAT) {
		t.Run(tt.name, func(t *testing.T) {
			a, err := aes.NewAES(tt.key)
			if err != nil {
				t.Fatal("NewDES error:", err)
			}

			switch tt.op {
			case encrypt:
				tt.dst = make([]byte, len(tt.plaintext))

				g := NewGCMSealer(a, tt.iv)
				g.WriteAD(tt.aad)
				if err := g.Write(tt.dst, tt.plaintext); err != nil {
					t.Errorf("Write() error = %v", err)
				}

				testutil.AssertBytesEqual(t, g.Tag(), tt.tag)
				testutil.AssertBytesEqual(t, tt.dst, tt.ciphertext)

			case decrypt:
				if tt.pass {
					tt.dst = make([]byte, len(tt.ciphertext))
				}

				g := NewGCMOpener(a, tt.iv)
				g.WriteAD(tt.aad)
				if err := g.Write(tt.ciphertext); err != nil {
					t.Errorf("Write() error = %v", err)
				}

				decrypter, err := g.Verify(tt.tag)
				testutil.AssertNilError(t, err, !tt.pass)
				if !tt.pass {
					return
				}

				if err := decrypter.Decrypt(tt.dst, tt.ciphertext); err != nil {
					t.Errorf("Decrypt() error = %v", err)
				}

				testutil.AssertBytesEqual(t, tt.dst, tt.plaintext)

			default:
				t.Fatalf("unknown operation %d", tt.op)
			}
		})
	}
}
