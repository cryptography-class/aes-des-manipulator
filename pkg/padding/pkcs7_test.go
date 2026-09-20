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
			name:      "invalid blocksize",
			data:      nil,
			blockSize: 0,
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
		name string
		data []byte
		want []byte
		err  error
	}{
		{
			name: "valid padding 1",
			data: []byte{1, 3, 2, 2},
			want: []byte{1, 3},
		},
		{
			name: "valid padding 2",
			data: []byte{1, 3, 3, 3},
			want: []byte{1},
		},
		{
			name: "valid padding 3",
			data: []byte{1, 2, 3, 4, 4, 4, 4, 4},
			want: []byte{1, 2, 3, 4},
		},
		{
			name: "valid padding 4",
			data: []byte{9, 8, 7, 6, 5, 4, 2, 2},
			want: []byte{9, 8, 7, 6, 5, 4},
		},
		{
			name: "empty data",
			data: []byte{},
			err:  ErrEmptyInput,
		},
		{
			name: "nil data",
			data: nil,
			err:  ErrEmptyInput,
		},
		{
			name: "invalid padding 1",
			data: []byte{1, 251},
			err:  ErrInvalidPadding,
		},
		{
			name: "invalid padding 2",
			data: []byte{1, 0},
			err:  ErrInvalidPadding,
		},
		{
			name: "invalid padding 3",
			data: []byte{1, 1, 1, 2},
			err:  ErrInvalidPadding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PKCS7Unpad(tt.data)
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}

			testutil.AssertDeepEqual(t, got, tt.want)
		})
	}
}
