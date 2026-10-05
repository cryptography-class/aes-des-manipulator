package orchestration

import (
	"io"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
	"github.com/cryptography-class/aes-des-manipulator/pkg/mode"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
)

func TestNewECBRunner(t *testing.T) {
	cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewDes() error: %v", err)
	}
	padder := padding.NewPKCS7()

	tests := []struct {
		name      string
		cipher    block.Cipher
		padder    *padding.Padder
		action    Action
		wantPanic bool
	}{
		{
			name:   "valid encrypter",
			cipher: cipher,
			padder: padder,
			action: Encrypt,
		},
		{
			name:   "valid decrypter",
			cipher: cipher,
			padder: padder,
			action: Decrypt,
		},
		{
			name:      "nil cipher",
			cipher:    nil,
			padder:    padder,
			action:    Encrypt,
			wantPanic: true,
		},
		{
			name:      "invalid action",
			cipher:    cipher,
			padder:    padder,
			action:    -1,
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			_, err := newECBRunner(tt.cipher, tt.padder, tt.action)
			if err != nil {
				t.Errorf("newECBRunner() error: %v", err)
			}
		})
	}
}

// encryptECB pads (if pad != nil) and encrypts plaintext block by block.
func encryptECB(t *testing.T, cipher block.Cipher, padder *padding.Padder, plain []byte) []byte {
	t.Helper()

	blockSize := cipher.BlockSize()
	if padder != nil {
		plain = padder.PadFunc(plain, blockSize)
	}

	if err := mode.NewECBEncrypter(cipher).Crypt(plain, plain); err != nil {
		t.Fatalf("mode.NewECBEncrypter(cipher).Crypt() error: %v", err)
	}

	return plain
}

func TestECBRunnerPreRun(t *testing.T) {
	cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewDes() error: %v", err)
	}
	padder := padding.NewPKCS7()

	tests := []struct {
		name    string
		cipher  block.Cipher
		padder  *padding.Padder
		action  Action
		src     io.ReaderAt
		size    int64
		outSize int64
		wantErr bool
	}{
		{
			name:    "valid pre-encrypt 1",
			cipher:  cipher,
			padder:  padder,
			action:  Encrypt,
			src:     newTestSource([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			size:    8,
			outSize: 16,
		},
		{
			name:    "valid pre-encrypt 2",
			cipher:  cipher,
			padder:  padder,
			action:  Encrypt,
			src:     newTestSource([]byte{1, 2, 3, 4}),
			size:    4,
			outSize: 8,
		},
		{
			name:    "size 0 pre-encrypt",
			cipher:  cipher,
			padder:  padder,
			action:  Encrypt,
			src:     newTestSource([]byte{}),
			size:    0,
			outSize: 8,
		},
		{
			name:    "valid pre-decrypt 1",
			cipher:  cipher,
			padder:  padder,
			action:  Decrypt,
			src:     newTestSource(encryptECB(t, cipher, padder, []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8})),
			size:    16,
			outSize: 8,
		},
		{
			name:    "valid pre-decrypt 2",
			cipher:  cipher,
			padder:  padder,
			action:  Decrypt,
			src:     newTestSource(encryptECB(t, cipher, padder, []byte{1, 2, 3, 4, 4, 4, 4, 4})),
			size:    8,
			outSize: 4,
		},
		{
			name:    "invalid size 1",
			cipher:  cipher,
			padder:  padder,
			action:  Decrypt,
			src:     newTestSource([]byte{1, 2, 3, 4, 4, 4, 4, 4}),
			size:    5,
			wantErr: true,
		},
		{
			name:    "invalid size 2",
			cipher:  cipher,
			padder:  padder,
			action:  Decrypt,
			src:     newTestSource([]byte{1, 2, 3, 4, 4, 4, 4, 4}),
			size:    0,
			wantErr: true,
		},
		{
			name:    "invalid padding",
			cipher:  cipher,
			padder:  padder,
			action:  Decrypt,
			src:     newTestSource(encryptECB(t, cipher, nil, []byte{1, 2, 3, 4, 4, 0, 4, 4})),
			size:    8,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, err := newECBRunner(tt.cipher, tt.padder, tt.action)
			if err != nil {
				t.Fatalf("newECBRunner() error: %v", err)
			}

			got, err := runner.PreRun(tt.src, tt.size)
			testutil.AssertNilError(t, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			testutil.AssertEqual(t, got, tt.outSize)
		})
	}
}
