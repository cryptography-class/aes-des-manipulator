package mode

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
)

func TestNewCBCEncrypter(t *testing.T) {
	cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("des.NewDES(): %v", err)
	}

	tests := []struct {
		name      string
		cipher    block.Cipher
		iv        []byte
		want      block.Cipher
		wantPanic bool
	}{
		{
			name:   "valid block cipher",
			cipher: cipher,
			iv:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
			want:   cipher,
		},
		{
			name:      "nil block cipher",
			cipher:    nil,
			iv:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			wantPanic: true,
		},
		{
			name:      "iv length mismatch",
			cipher:    cipher,
			iv:        []byte{1, 2, 3, 4, 5, 6, 7},
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			crypter := NewCBCEncrypter(tt.cipher, tt.iv)
			got, ok := crypter.(*cbcEncrypter)
			if !ok {
				t.Fatalf("NewCBCEncrypter() did not return a cbcEncrypter")
			}

			testutil.AssertDeepEqual(t, got.cipher, tt.want)
		})
	}
}

func TestCBCEncrypterBlockSize(t *testing.T) {
	t.Run("8 bytes", func(t *testing.T) {
		cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatalf("des.NewDES(): %v", err)
		}

		crypt := NewCBCEncrypter(cipher, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		testutil.AssertEqual(t, crypt.BlockSize(), cipher.BlockSize())
	})
}

func TestCBCEncrypterCrypt(t *testing.T) {
	buffer := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	tests := []struct {
		name string
		key  []byte
		iv   []byte
		src  []byte
		dst  []byte
		want []byte
		err  error
	}{
		{
			// https://github.com/torvalds/linux/blob/master/crypto/testmgr.h
			name: "FIPS 81 block 1",
			key:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			iv:   []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
			src:  []byte("Now is t"),
			dst:  make([]byte, 8),
			want: []byte{0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c},
		},
		{
			// https://github.com/torvalds/linux/blob/master/crypto/testmgr.h
			name: "FIPS 81 block 2",
			key:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			iv:   []byte{0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c},
			src:  []byte("he time "),
			dst:  make([]byte, 8),
			want: []byte{0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38, 0x9c, 0x0f},
		},
		{
			// https://github.com/torvalds/linux/blob/master/crypto/testmgr.h
			name: "FIPS 81 block 3",
			key:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			iv:   []byte{0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38, 0x9c, 0x0f},
			src:  []byte("for all "),
			dst:  make([]byte, 8),
			want: []byte{0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6},
		},
		{
			// https://github.com/torvalds/linux/blob/master/crypto/testmgr.h
			name: "FIPS 81 full message",
			key:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			iv:   []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
			src:  []byte("Now is the time for all "),
			dst:  make([]byte, 24),
			want: []byte{
				0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c,
				0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38, 0x9c, 0x0f,
				0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6,
			},
		},
		{
			name: "dst and src length mismatch",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			iv:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
			src:  []byte{1},
			dst:  []byte{1, 2},
			err:  ErrLengthMismatch,
		},
		{
			name: "src length not a multiple of block size",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			iv:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
			src:  []byte{1, 2},
			dst:  []byte{1, 2},
			err:  ErrNotFullBlocks,
		},
		{
			name: "src and dst partially overlap",
			key:  []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
			iv:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
			src:  buffer[1:],
			dst:  buffer[:8],
			err:  ErrInexactOverlap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := des.NewDES(tt.key)
			if err != nil {
				t.Fatalf("des.NewDES(): %v", err)
			}
			crypter := NewCBCEncrypter(cipher, tt.iv)

			err = crypter.Crypt(tt.dst, tt.src)
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}

			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}
