package gcm

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/aead"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/aes"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
)

func TestNewGCMSealerOpener(t *testing.T) {
	wrong, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewDES() error = %v", err)
	}

	correct, err := aes.NewAES([]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewAES() error = %v", err)
	}

	tests := []struct {
		name      string
		cipher    block.Cipher
		iv        []byte
		wantPanic bool
	}{
		{
			name:   "valid",
			cipher: correct,
			iv:     make([]byte, NonceSize),
		},
		{
			name:      "nil cipher",
			cipher:    nil,
			iv:        make([]byte, NonceSize),
			wantPanic: true,
		},
		{
			name:      "wrong block size cipher",
			cipher:    wrong,
			iv:        make([]byte, NonceSize),
			wantPanic: true,
		},
		{
			name:      "wrong iv length",
			cipher:    correct,
			iv:        make([]byte, NonceSize+1),
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			_ = NewGCMSealer(tt.cipher, tt.iv)
			_ = NewGCMOpener(tt.cipher, tt.iv)
		})
	}
}

func TestInvalidWrite(t *testing.T) {
	buffer := make([]byte, blockSize+1)
	cipher, err := aes.NewAES([]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewAES() error = %v", err)
	}

	iv := make([]byte, NonceSize)

	t.Run("sealer length mismatch", func(t *testing.T) {
		err := NewGCMSealer(cipher, iv).Write(buffer[:3], buffer[5:])
		testutil.AssertError(t, err, aead.ErrLengthMismatch)
	})

	t.Run("sealer overlap", func(t *testing.T) {
		err := NewGCMSealer(cipher, iv).Write(buffer[:3], buffer[1:4])
		testutil.AssertError(t, err, aead.ErrInexactOverlap)
	})

	t.Run("sealer overflow", func(t *testing.T) {
		sealer := NewGCMSealer(cipher, iv)
		s, ok := sealer.(*gcmSealer)
		if !ok {
			t.Fatalf("sealer is not gcmSealer")
		}
		s.hash.ciphertextLength = maxBytes - 1

		err := s.Write(buffer, buffer)
		testutil.AssertError(t, err, aead.ErrTooMuchData)
	})

	t.Run("opener overflow", func(t *testing.T) {
		sealer := NewGCMOpener(cipher, iv)
		s, ok := sealer.(*gcmOpener)
		if !ok {
			t.Fatalf("sealer is not gcmSealer")
		}
		s.hash.ciphertextLength = maxBytes - 1

		err := s.Write(buffer)
		testutil.AssertError(t, err, aead.ErrTooMuchData)
	})

	t.Run("decrypter length mismatch", func(t *testing.T) {
		err := newGCMDecrypter(cipher, iv).Decrypt(buffer[:3], buffer[5:])
		testutil.AssertError(t, err, aead.ErrLengthMismatch)
	})

	t.Run("decrypter overlap", func(t *testing.T) {
		err := newGCMDecrypter(cipher, iv).Decrypt(buffer[:3], buffer[1:4])
		testutil.AssertError(t, err, aead.ErrInexactOverlap)
	})

	t.Run("decrypter overflow", func(t *testing.T) {
		decrypter := newGCMDecrypter(cipher, iv)
		decrypter.pos = maxBytes - 1
		err := decrypter.Decrypt(buffer, buffer)
		testutil.AssertError(t, err, aead.ErrTooMuchData)
	})
}

func TestDecrypterAt(t *testing.T) {
	cipher, err := aes.NewAES([]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewAES() error = %v", err)
	}

	iv := make([]byte, NonceSize)

	tests := []struct {
		name   string
		cipher block.Cipher
		iv     []byte
		blocks uint64
		err    error
	}{
		{
			name:   "valid",
			cipher: cipher,
			iv:     iv,
			blocks: 0,
		},
		{
			name:   "overflow",
			cipher: cipher,
			iv:     iv,
			blocks: maxBlocks,
			err:    aead.ErrTooMuchData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newGCMDecrypter(tt.cipher, tt.iv).At(tt.blocks)
			testutil.AssertError(t, err, tt.err)
		})
	}
}

func TestConstants(t *testing.T) {
	g := gcm{}
	t.Run("nonce size", func(t *testing.T) {
		testutil.AssertEqual(t, g.NonceSize(), NonceSize)
		testutil.AssertEqual(t, g.NonceSize(), 12)
	})

	t.Run("tag size", func(t *testing.T) {
		testutil.AssertEqual(t, g.Overhead(), TagSize)
		testutil.AssertEqual(t, g.Overhead(), 16)
	})
}

func TestInvalidTagLength(t *testing.T) {
	cipher, err := aes.NewAES([]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewAES() error = %v", err)
	}

	iv := make([]byte, NonceSize)
	t.Run("opener invalid tag length", func(t *testing.T) {
		opener := NewGCMOpener(cipher, iv)
		_, err := opener.Verify(make([]byte, TagSize-1))
		testutil.AssertError(t, err, aead.ErrInvalidAuthentication)
	})
}
