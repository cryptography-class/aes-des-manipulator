package des

import (
	"bytes"
	"embed"
	"fmt"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

// Huge thanks to
// https://stackoverflow.com/questions/21341794/data-encryption-standard-test-vectors
// for providing structured test data from
// "Validating the Correctness of Hardware Implementations of the NBS Data Encryption Standard"
// NBS Special Publication 500-20, 1980.

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

// TestCase is a test case for DES Encrypt/Decrypt/Roundtrip.
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
	key, err := r.Hex("KEY", KeyLength)
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
			d, err := NewDES(tt.key)
			if err != nil {
				t.Fatal("NewDES error:", err)
			}

			switch tt.op {
			case Encrypt:
				d.Encrypt(tt.dst, tt.src)

			case Decrypt:
				d.Decrypt(tt.dst, tt.src)

			case Roundtrip:
				d.Encrypt(tt.dst, tt.src)
				d.Decrypt(tt.dst, tt.dst)

			default:
				t.Fatalf("unknown operation %d", tt.op)
			}

			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}

func testCrypt(t *testing.T, tests []TestCase, forward bool) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			d, err := NewDES(tt.key)
			if err != nil {
				t.Fatal("NewDES error:", err)
			}

			if forward {
				d.Encrypt(tt.dst, tt.src)
			} else {
				d.Decrypt(tt.dst, tt.src)
			}
			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}

// OverlapBuffer is used for checking partial overlaps which are not allowed by block.Cipher.
var OverlapBuffer = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

// EdgeCases is a collection of tests that check src and dst.
var EdgeCases = []TestCase{
	{
		name:      "dst size mismatch",
		key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
		src:       make([]byte, BlockSize),
		dst:       make([]byte, BlockSize-1),
		wantPanic: true,
	},
	{
		name:      "src size mismatch",
		key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
		src:       make([]byte, BlockSize-1),
		dst:       make([]byte, BlockSize),
		wantPanic: true,
	},
	{
		name:      "dst and src partially overlap",
		key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
		src:       OverlapBuffer[:8],
		dst:       OverlapBuffer[1:],
		wantPanic: true,
	},
}

func TestEncrypt(t *testing.T) {
	tests := []TestCase{
		{
			// source: https://arxiv.org/pdf/2301.05530
			name: "valid key 1",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			dst:  make([]byte, BlockSize),
			want: []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05},
		},
	}

	tests = append(tests, EdgeCases...)
	testCrypt(t, tests, true)
}

func TestDecrypt(t *testing.T) {
	tests := []TestCase{
		{
			// source: https://arxiv.org/pdf/2301.05530
			name: "valid key 1",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:  []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05},
			dst:  make([]byte, BlockSize),
			want: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		},
	}

	tests = append(tests, EdgeCases...)
	testCrypt(t, tests, false)
}
