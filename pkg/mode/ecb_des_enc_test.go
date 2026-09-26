package mode

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
)

func TestNewECBEncrypter(t *testing.T) {
	t.Run("valid block cipher", func(t *testing.T) {
		cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatalf("des.NewDES(): %v", err)
		}

		crypt := NewECBEncrypter(cipher)
		got, ok := crypt.(*ecbEncrypter)
		if !ok {
			t.Fatalf("NewECBEncrypter() did not return a ecbEncrypter")
		}

		testutil.AssertDeepEqual(t, got.cipher, cipher)
	})

	t.Run("nil block cipher", func(t *testing.T) {
		defer func() {
			testutil.AssertPanic(t, recover(), true)
		}()
		_ = NewECBEncrypter(nil)
	})
}

func TestECBEncrypterBlockSize(t *testing.T) {
	t.Run("8 bytes", func(t *testing.T) {
		cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatalf("des.NewDES(): %v", err)
		}

		crypt := NewECBEncrypter(cipher)
		testutil.AssertEqual(t, crypt.BlockSize(), cipher.BlockSize())
	})
}

func TestECBEncrypterCrypt(t *testing.T) {
	cipher, err := des.NewDES([]byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1})
	if err != nil {
		t.Fatalf("des.NewDES(): %v", err)
	}

	overlap := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
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
			src:    []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			dst:    make([]byte, cipher.BlockSize()),
			want:   []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05},
		},
		{
			name:   "2 blocks",
			cipher: cipher,
			src: []byte{
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
			},
			dst: make([]byte, cipher.BlockSize()*2),
			want: []byte{
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
			},
		},
		{
			name:   "3 blocks",
			cipher: cipher,
			src: []byte{
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
			},
			dst: make([]byte, cipher.BlockSize()*3),
			want: []byte{
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
				0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05,
			},
		},
		{
			name:   "dst and src overlap",
			cipher: cipher,
			src:    overlap,
			dst:    overlap,
			want:   []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05},
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
			crypter := NewECBEncrypter(tt.cipher)

			err := crypter.Crypt(tt.dst, tt.src)
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}

			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}
