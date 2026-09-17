package des

import (
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
			// because the implementation ignore parity bits
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

type encryptTest struct {
	name      string
	key       []byte
	src       []byte
	dst       []byte
	want      []byte
	wantPanic bool
}

func TestEncrypt(t *testing.T) {
	tests := []encryptTest{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			d, err := NewDES(tt.key)
			if err != nil {
				t.Fatal("NewDES error:", err)
			}

			d.Encrypt(tt.dst, tt.src)
			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}
