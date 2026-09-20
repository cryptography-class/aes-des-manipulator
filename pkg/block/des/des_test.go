package des

import (
	"embed"
	"fmt"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestNewDES(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		want      [16]uint64
		wantError bool
	}{
		{
			// source: https://arxiv.org/pdf/2301.05530
			name: "valid key",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			want: [16]uint64{
				0x1B02EFFC7072, 0x79AED9DBC9E5, 0x55FC8A42CF99, 0x72ADD6DB351D,
				0x7CEC07EB53A8, 0x63A53E507B2F, 0xEC84B7F618BC, 0xF78A3AC13BFB,
				0xE0DBEBEDE781, 0xB1F347BA464F, 0x215FD3DED386, 0x7571F59467E9,
				0x97C5D1FABA41, 0x5F43B7F2E73A, 0xBF918D3D3F0A, 0xCB3D8B0E17F5,
			},
		},
		{
			// should produce the same key as the valid key test case
			// because the implementation ignores parity bits
			name: "parity bits ignored",
			key:  []byte{0x12, 0x35, 0x56, 0x78, 0x9A, 0xBD, 0xDE, 0xF0},
			want: [16]uint64{
				0x1B02EFFC7072, 0x79AED9DBC9E5, 0x55FC8A42CF99, 0x72ADD6DB351D,
				0x7CEC07EB53A8, 0x63A53E507B2F, 0xEC84B7F618BC, 0xF78A3AC13BFB,
				0xE0DBEBEDE781, 0xB1F347BA464F, 0x215FD3DED386, 0x7571F59467E9,
				0x97C5D1FABA41, 0x5F43B7F2E73A, 0xBF918D3D3F0A, 0xCB3D8B0E17F5,
			},
		},
		{
			// all zeroes
			name: "0x0 key",
			key:  []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			want: [16]uint64{
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,
			},
		},
		{
			// all ones
			name: "0xFF key",
			key:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			want: [16]uint64{
				0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF,
				0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF,
				0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF,
				0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF,
			},
		},
		{
			name:      "short key error",
			key:       []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			wantError: true,
		},
		{
			name:      "long key error",
			key:       []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			wantError: true,
		},
		{
			name:      "nil key error",
			key:       nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDES(tt.key)
			testutil.AssertNilError(t, err, tt.wantError)
			if tt.wantError {
				return
			}

			d, ok := got.(*des)
			if !ok {
				t.Fatalf("NewDES() did not return a des")
			}
			testutil.AssertEqual(t, d.subkeys, tt.want)
		})
	}
}

func TestBlockSize(t *testing.T) {
	t.Run("block size", func(t *testing.T) {
		var d des
		testutil.AssertEqual(t, d.BlockSize(), blockSize)
		testutil.AssertEqual(t, d.BlockSize(), 8)
	})
}

// Huge thanks to
// https://stackoverflow.com/questions/21341794/data-encryption-standard-test-vectors
// for providing structured test data from
// "Validating the Correctness of Hardware Implementations of the NBS Data Encryption Standard"
// NBS Special Publication 500-20, 1980.

//go:embed testdata/*/*.txt
var testdataFS embed.FS

const (
	encryptMatch   = "testdata/encrypt/*.txt"
	decryptMatch   = "testdata/decrypt/*.txt"
	roundtripMatch = "testdata/roundtrip/*.txt"
)

type cryptTest struct {
	name      string
	key       []byte
	src       []byte
	dst       []byte
	want      []byte
	wantPanic bool
}

func (ct cryptTest) Parse(name string, fields []string) (cryptTest, error) {
	if len(fields) != 3 {
		return cryptTest{}, fmt.Errorf("%s: expected 3 fields, got: %d", name, len(fields))
	}

	key, err := testutil.ParseHex(name, fields[0], blockSize)
	if err != nil {
		return cryptTest{}, err
	}

	src, err := testutil.ParseHex(name, fields[1], blockSize)
	if err != nil {
		return cryptTest{}, err
	}

	want, err := testutil.ParseHex(name, fields[2], blockSize)
	if err != nil {
		return cryptTest{}, err
	}

	return cryptTest{
		name: name,
		key:  key,
		src:  src,
		dst:  make([]byte, blockSize),
		want: want,
	}, nil
}

func testCrypt(t *testing.T, tests []cryptTest, forward bool) {
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

func TestEncrypt(t *testing.T) {
	folder := &testutil.TestFolder{
		FS:    &testdataFS,
		Match: encryptMatch,
	}

	buffer := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	tests := []cryptTest{
		{
			// source: https://arxiv.org/pdf/2301.05530
			name: "valid key 1",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			dst:  make([]byte, blockSize),
			want: []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05},
		},
		{
			name:      "dst size mismatch",
			key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:       make([]byte, blockSize),
			dst:       make([]byte, blockSize-1),
			wantPanic: true,
		},
		{
			name:      "src size mismatch",
			key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:       make([]byte, blockSize-1),
			dst:       make([]byte, blockSize),
			wantPanic: true,
		},
		{
			name:      "dst and src partially overlap",
			key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:       buffer,
			dst:       buffer[1:],
			wantPanic: true,
		},
	}

	tests = append(tests, testutil.ParseTests[cryptTest](t, folder)...)
	testCrypt(t, tests, true)
}

func TestDecrypt(t *testing.T) {
	folder := &testutil.TestFolder{
		FS:    &testdataFS,
		Match: decryptMatch,
	}

	buffer := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	tests := []cryptTest{
		{
			// source: https://arxiv.org/pdf/2301.05530
			name: "valid key 1",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:  []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05},
			dst:  make([]byte, blockSize),
			want: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		},
		{
			name:      "dst size mismatch",
			key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:       make([]byte, blockSize),
			dst:       make([]byte, blockSize-1),
			wantPanic: true,
		},
		{
			name:      "src size mismatch",
			key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:       make([]byte, blockSize-1),
			dst:       make([]byte, blockSize),
			wantPanic: true,
		},
		{
			name:      "dst and src partially overlap",
			key:       []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			src:       buffer,
			dst:       buffer[1:],
			wantPanic: true,
		},
	}

	tests = append(tests, testutil.ParseTests[cryptTest](t, folder)...)
	testCrypt(t, tests, false)
}

func TestRoundtrip(t *testing.T) {
	folder := &testutil.TestFolder{
		FS:    &testdataFS,
		Match: roundtripMatch,
	}

	tests := append([]cryptTest{}, testutil.ParseTests[cryptTest](t, folder)...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDES(tt.key)
			if err != nil {
				t.Fatal("NewDES error:", err)
			}

			d.Encrypt(tt.dst, tt.src)
			d.Decrypt(tt.dst, tt.dst)
			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}
