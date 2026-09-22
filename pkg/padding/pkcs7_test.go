package padding

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestPKCS7Pad(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
		wantPanic bool
	}{
		{
			name:      "padding 1",
			data:      []byte{1, 2, 3, 4},
			blockSize: 8,
			want:      []byte{1, 2, 3, 4, 4, 4, 4, 4},
		},
		{
			name:      "padding 2",
			data:      []byte{1},
			blockSize: 16,
			want:      []byte{1, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
		},
		{
			name:      "empty data",
			data:      []byte{},
			blockSize: 4,
			want:      []byte{4, 4, 4, 4},
		},
		{
			name:      "nil data",
			data:      nil,
			blockSize: 4,
			want:      []byte{4, 4, 4, 4},
		},
		{
			name:      "invalid blocksize 1",
			data:      nil,
			blockSize: 0,
			wantPanic: true,
		},
		{
			name:      "invalid blocksize 2",
			data:      nil,
			blockSize: 256,
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			got := PKCS7Pad(tt.data, tt.blockSize)
			testutil.AssertDeepEqual(t, got, tt.want)
		})
	}
}

func TestPKCS7Unpad(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
		wantPanic bool
		err       error
	}{
		{
			name:      "valid padding 1",
			data:      []byte{1, 3, 2, 2},
			blockSize: 4,
			want:      []byte{1, 3},
		},
		{
			name:      "valid padding 2",
			data:      []byte{1, 3, 3, 3},
			blockSize: 4,
			want:      []byte{1},
		},
		{
			name:      "valid padding 3",
			data:      []byte{1, 2, 3, 4, 4, 4, 4, 4},
			blockSize: 4,
			want:      []byte{1, 2, 3, 4},
		},
		{
			name:      "valid padding 4",
			data:      []byte{9, 8, 7, 6, 5, 4, 2, 2},
			blockSize: 8,
			want:      []byte{9, 8, 7, 6, 5, 4},
		},
		{
			name:      "invalid blocksize",
			data:      []byte{1, 1},
			blockSize: 0,
			wantPanic: true,
		},
		{
			name:      "empty data",
			data:      []byte{},
			blockSize: 8,
			err:       ErrEmptyInput,
		},
		{
			name:      "nil data",
			data:      nil,
			blockSize: 8,
			err:       ErrEmptyInput,
		},
		{
			// len(data)%blockSize
			name:      "invalid padding 1",
			data:      []byte{1, 1},
			blockSize: 3,
			err:       ErrInvalidPadding,
		},
		{
			// Invalid padding byte
			name:      "invalid padding 2",
			data:      []byte{1, 0},
			blockSize: 2,
			err:       ErrInvalidPadding,
		},
		{
			// Invalid padding byte
			name:      "invalid padding 3",
			data:      []byte{1, 1, 1, 2},
			blockSize: 4,
			err:       ErrInvalidPadding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			got, err := PKCS7Unpad(tt.data, tt.blockSize)
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}

			testutil.AssertDeepEqual(t, got, tt.want)
		})
	}
}

func TestPKS7RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
	}{
		{
			name:      "valid padding 1",
			data:      []byte{1, 3, 2, 2},
			blockSize: 8,
		},
		{
			name:      "valid padding 1",
			data:      []byte{1, 3, 2, 2},
			blockSize: 4,
		},
		{
			name:      "valid padding 1",
			data:      []byte{1, 3, 2, 2},
			blockSize: 2,
		},
		{
			name:      "valid padding 1",
			data:      []byte{1, 2},
			blockSize: 3,
		},
		{
			name:      "valid padding 1",
			data:      []byte{},
			blockSize: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pad := PKCS7Pad(tt.data, tt.blockSize)
			got, err := PKCS7Unpad(pad, tt.blockSize)
			if err != nil {
				t.Fatalf("PKCS7Unpad() error = %v", err)
			}

			testutil.AssertDeepEqual(t, got, tt.data)
		})
	}
}
