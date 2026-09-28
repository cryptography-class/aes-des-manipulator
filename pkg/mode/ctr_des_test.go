package mode

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
)

func TestNewCTREncrypter(t *testing.T) {
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

			crypter := NewCTREncrypter(tt.cipher, tt.iv)
			got, ok := crypter.(*ctrCrypter)
			if !ok {
				t.Fatalf("NewCTREncrypter() did not return a ctrCrypter")
			}

			testutil.AssertDeepEqual(t, got.cipher, tt.want)
		})
	}
}

func TestNewCTRDecrypter(t *testing.T) {
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

			crypter := NewCTRDecrypter(tt.cipher, tt.iv)
			got, ok := crypter.(*ctrCrypter)
			if !ok {
				t.Fatalf("NewCTRDecrypter() did not return a ctrCrypter")
			}

			testutil.AssertDeepEqual(t, got.cipher, tt.want)
		})
	}
}

func TestCTRBlockSize(t *testing.T) {
	t.Run("8 bytes", func(t *testing.T) {
		cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatalf("des.NewDES(): %v", err)
		}

		crypt := NewCTREncrypter(cipher, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		testutil.AssertEqual(t, crypt.BlockSize(), cipher.BlockSize())
	})
}

func TestCTREncrypterCrypt(t *testing.T) {
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	iv := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}

	inPlace := []byte("Now is the time for all ")
	buffer := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	// generated with the crypto/des ctr implementation
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
			name: "1 block",
			key:  key,
			iv:   iv,
			src:  []byte("Now is t"),
			dst:  make([]byte, 8),
			want: []byte{0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51},
		},
		{
			name: "3 blocks",
			key:  key,
			iv:   iv,
			src:  []byte("Now is the time for all "),
			dst:  make([]byte, 24),
			want: []byte{
				0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51,
				0x16, 0x3a, 0x8c, 0xa0, 0xff, 0xc9, 0x4c, 0x27,
				0xfa, 0x2f, 0x80, 0xf4, 0x80, 0xb8, 0x6f, 0x75,
			},
		},
		{
			name: "empty",
			key:  key,
			iv:   iv,
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name: "1 byte",
			key:  key,
			iv:   iv,
			src:  []byte("N"),
			dst:  make([]byte, 1),
			want: []byte{0xf3},
		},
		{
			name: "7 bytes (partial block)",
			key:  key,
			iv:   iv,
			src:  []byte("Now is "),
			dst:  make([]byte, 7),
			want: []byte{0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e},
		},
		{
			name: "9 bytes (block + 1)",
			key:  key,
			iv:   iv,
			src:  []byte("Now is th"),
			dst:  make([]byte, 9),
			want: []byte{0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51, 0x16},
		},
		{
			name: "20 bytes (2 blocks + partial)",
			key:  key,
			iv:   iv,
			src:  []byte("Now is the time for "),
			dst:  make([]byte, 20),
			want: []byte{
				0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51,
				0x16, 0x3a, 0x8c, 0xa0, 0xff, 0xc9, 0x4c, 0x27,
				0xfa, 0x2f, 0x80, 0xf4,
			},
		},
		{
			name: "counter carry into second-lowest byte",
			key:  key,
			iv:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff},
			src:  []byte("Now is the time for all "),
			dst:  make([]byte, 24),
			want: []byte{
				0x48, 0xeb, 0x53, 0xa7, 0x64, 0x8d, 0x23, 0xc0,
				0xb3, 0x2f, 0xc2, 0x06, 0xfe, 0x81, 0xa8, 0x4e,
				0x50, 0x85, 0x7b, 0x19, 0x33, 0xdb, 0x09, 0x3b,
			},
		},
		{
			name: "counter wraparound, all-ones IV",
			key:  key,
			iv:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			src:  []byte("Now is the time for all "),
			dst:  make([]byte, 24),
			want: []byte{
				0x17, 0x1c, 0x54, 0x76, 0x9a, 0x1c, 0xfe, 0x72,
				0xbd, 0xb1, 0x6f, 0x83, 0x49, 0x05, 0x58, 0x2d,
				0x96, 0xe3, 0x25, 0x00, 0xf4, 0xff, 0x92, 0x93,
			},
		},
		{
			name: "counter wraparound mid-message (FD, FE, FF, 00, 01)",
			key:  key,
			iv:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd},
			src:  []byte("Now is the time for all good men to come"),
			dst:  make([]byte, 40),
			want: []byte{
				0x28, 0x4b, 0x9d, 0x84, 0x42, 0x63, 0xe6, 0x7e,
				0xd4, 0x2a, 0x49, 0x3f, 0x2c, 0xbb, 0x50, 0x73,
				0x3f, 0x1c, 0x51, 0x76, 0x92, 0x03, 0xb2, 0x26,
				0xb2, 0xbb, 0x20, 0x93, 0x00, 0x05, 0x58, 0x63,
				0xd0, 0xf8, 0x38, 0x00, 0xf6, 0xfc, 0x93, 0xd6,
			},
		},
		{
			// exact aliasing is valid for a stream cipher.
			name: "dst and src overlap",
			key:  key,
			iv:   iv,
			src:  inPlace,
			dst:  inPlace,
			want: []byte{
				0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51,
				0x16, 0x3a, 0x8c, 0xa0, 0xff, 0xc9, 0x4c, 0x27,
				0xfa, 0x2f, 0x80, 0xf4, 0x80, 0xb8, 0x6f, 0x75,
			},
		},
		{
			name: "dst longer than src",
			key:  key,
			iv:   iv,
			src:  []byte{1},
			dst:  []byte{1, 2},
			err:  ErrLengthMismatch,
		},
		{
			name: "dst shorter than src",
			key:  key,
			iv:   iv,
			src:  []byte{1, 2},
			dst:  []byte{1},
			err:  ErrLengthMismatch,
		},
		{
			name: "src and dst partially overlap",
			key:  key,
			iv:   iv,
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
			crypter := NewCTREncrypter(cipher, tt.iv)

			err = crypter.Crypt(tt.dst, tt.src)
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}

			testutil.AssertDeepEqual(t, tt.dst, tt.want)
		})
	}
}
