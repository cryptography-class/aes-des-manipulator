package mode

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
)

func TestNewECBDecrypter(t *testing.T) {
	t.Run("valid block cipher", func(t *testing.T) {
		cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatalf("des.NewDES(): %v", err)
		}

		crypt := NewECBDecrypter(cipher)
		got, ok := crypt.(*ecbDecrypter)
		if !ok {
			t.Fatalf("NewECBDecrypter() did not return a ecbDecrypter")
		}

		testutil.AssertDeepEqual(t, got.cipher, cipher)
	})

	t.Run("nil block cipher", func(t *testing.T) {
		defer func() {
			testutil.AssertPanic(t, recover(), true)
		}()
		_ = NewECBDecrypter(nil)
	})
}

func TestECBDecrypterBlockSize(t *testing.T) {
	t.Run("8 bytes", func(t *testing.T) {
		cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatalf("des.NewDES(): %v", err)
		}

		crypt := NewECBDecrypter(cipher)
		testutil.AssertEqual(t, crypt.BlockSize(), cipher.BlockSize())
	})
}

func TestECBDecrypterCrypt(t *testing.T) {
	cipher, err := des.NewDES([]byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1})
	if err != nil {
		t.Fatalf("des.NewDES(): %v", err)
	}

	overlap := []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}
	buffer := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	tests := []struct {
		name   string
		cipher block.Cipher
		src    []byte
		dst    []byte
		want   []byte
		err    error
	}{
		{
			name:   "1 block",
			cipher: cipher,
			src:    []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05},
			dst:    make([]byte, cipher.BlockSize()),
			want:   []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		},
		{
			name:   "2 blocks",
			cipher: cipher,
			src: []byte{
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
			},
			dst: make([]byte, cipher.BlockSize()*2),
			want: []byte{
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
			},
		},
		{
			name:   "3 blocks",
			cipher: cipher,
			src: []byte{
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
			},
			dst: make([]byte, cipher.BlockSize()*3),
			want: []byte{
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
			},
		},
		{
			name:   "dst and src overlap",
			cipher: cipher,
			src:    overlap,
			dst:    overlap,
			want:   []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		},
		{
			name:   "dst and src length mismatch",
			cipher: cipher,
			src:    []byte{1},
			dst:    []byte{1, 2},
			err:    ErrLengthMismatch,
		},
		{
			name:   "src length not a multiple of block size",
			cipher: cipher,
			src:    []byte{1, 2},
			dst:    []byte{1, 2},
			err:    ErrNotFullBlocks,
		},
		{
			name:   "src and dst partially overlap",
			cipher: cipher,
			src:    buffer[1:],
			dst:    buffer[:8],
			err:    ErrInexactOverlap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypter := NewECBDecrypter(tt.cipher)

			err := crypter.Crypt(tt.dst, tt.src)
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}

			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}
