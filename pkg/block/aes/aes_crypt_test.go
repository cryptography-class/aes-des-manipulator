package aes

import (
	"bytes"
	"embed"
	"fmt"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

//go:embed testdata/*.rsp
var TestDataFS embed.FS

type operation int8

const (
	Encrypt operation = iota
	Decrypt
	Roundtrip
)

const (
	Match = "testdata/*.rsp"

	EncryptSection   = "ENCRYPT"
	DecryptSection   = "DECRYPT"
	RoundtripSection = "ROUNDTRIP"
)

// TestCase is a single test case for AES Encrypt/Decrypt/Roundtrip.
type TestCase struct {
	name      string
	op        operation
	key       []byte
	src       []byte
	dst       []byte
	want      []byte
	wantPanic bool
}

func ParseKAT(r testutil.Record) (TestCase, error) {
	var zero TestCase
	key, err := r.Hex("KEY", KeyLength128, KeyLength192, KeyLength256)
	if err != nil {
		return zero, err
	}

	var src, want []byte
	var op operation
	switch r.Section {
	case EncryptSection:
		op = Encrypt
		src, err = r.Hex("PLAINTEXT", BlockSize)
		if err != nil {
			return zero, err
		}

		want, err = r.Hex("CIPHERTEXT", BlockSize)
		if err != nil {
			return zero, err
		}

	case DecryptSection:
		op = Decrypt
		src, err = r.Hex("CIPHERTEXT", BlockSize)
		if err != nil {
			return zero, err
		}

		want, err = r.Hex("PLAINTEXT", BlockSize)
		if err != nil {
			return zero, err
		}

	case RoundtripSection:
		op = Roundtrip
		src, err = r.Hex("PLAINTEXT", BlockSize)
		if err != nil {
			return zero, err
		}

		want = bytes.Clone(src)

	default:
		return zero, fmt.Errorf("unknown section %q", r.Section)
	}

	return TestCase{
		name: r.Name,
		op:   op,
		key:  key,
		src:  src,
		dst:  make([]byte, BlockSize),
		want: want,
	}, nil
}

func TestKAT(t *testing.T) {
	folder := &testutil.TestFolder{
		FS:    &TestDataFS,
		Match: Match,
	}

	for _, tt := range testutil.ParseTests(t, folder, ParseKAT) {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAES(tt.key)
			if err != nil {
				t.Fatal("NewDES error:", err)
			}

			switch tt.op {
			case Encrypt:
				a.Encrypt(tt.dst, tt.src)

			case Decrypt:
				a.Decrypt(tt.dst, tt.src)

			case Roundtrip:
				a.Encrypt(tt.dst, tt.src)
				a.Decrypt(tt.dst, tt.dst)

			default:
				t.Fatalf("unknown operation %d", tt.op)
			}

			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}

// OverlapBuffer is used for checking partial overlaps which are not allowed by block.Cipher.
var OverlapBuffer = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff}

// EdgeCases is a collection of tests that check src and dst.
var EdgeCases = []TestCase{
	{
		name:      "dst size mismatch",
		key:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		src:       make([]byte, BlockSize),
		dst:       make([]byte, BlockSize-1),
		wantPanic: true,
	},
	{
		name:      "src size mismatch",
		key:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		src:       make([]byte, BlockSize-1),
		dst:       make([]byte, BlockSize),
		wantPanic: true,
	},
	{
		name:      "dst and src partially overlap",
		key:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		src:       OverlapBuffer[:16],
		dst:       OverlapBuffer[1:],
		wantPanic: true,
	},
}

func testCrypt(t *testing.T, tests []TestCase, forward bool) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			a, err := NewAES(tt.key)
			if err != nil {
				t.Fatal("NewAES error:", err)
			}

			if forward {
				a.Encrypt(tt.dst, tt.src)
			} else {
				a.Decrypt(tt.dst, tt.src)
			}
			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}

func TestEncrypt(t *testing.T) {
	tests := []TestCase{
		{
			// source: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
			name: "KAT 1",
			key:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			src:  []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			dst:  make([]byte, BlockSize),
			want: []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
		},
	}
	tests = append(tests, EdgeCases...)
	testCrypt(t, tests, true)
}

func TestDecrypt(t *testing.T) {
	tests := []TestCase{
		{
			// source: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
			name: "KAT 1",
			key:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			src:  []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
			dst:  make([]byte, BlockSize),
			want: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		},
	}
	tests = append(tests, EdgeCases...)
	testCrypt(t, tests, false)
}
