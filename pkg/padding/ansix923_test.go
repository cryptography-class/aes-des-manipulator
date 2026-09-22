package padding

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestANSIX923Pad(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
		wantPanic bool
	}{
		{
			name:      "padding 1",
			data:      []byte{1, 2, 3},
			blockSize: 6,
			want:      []byte{1, 2, 3, 0, 0, 3},
		},
		{
			name:      "padding 2",
			data:      []byte{1, 2, 3, 4},
			blockSize: 4,
			want:      []byte{1, 2, 3, 4, 0, 0, 0, 4},
		},
		{
			name:      "empty data",
			data:      []byte{},
			blockSize: 4,
			want:      []byte{0, 0, 0, 4},
		},
		{
			name:      "nil data",
			data:      nil,
			blockSize: 4,
			want:      []byte{0, 0, 0, 4},
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

			got := ANSIX923Pad(tt.data, tt.blockSize)
			testutil.AssertDeepEqual(t, got, tt.want)
		})
	}
}

func TestANSIX923Unpad(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
		err       error
		wantPanic bool
	}{
		{
			name:      "valid padding 1",
			data:      []byte{1, 3, 0, 2},
			blockSize: 4,
			want:      []byte{1, 3},
		},
		{
			name:      "valid padding 2",
			data:      []byte{1, 0, 0, 3},
			blockSize: 4,
			want:      []byte{1},
		},
		{
			name:      "valid padding 3",
			data:      []byte{1, 2, 3, 4, 0, 0, 0, 4},
			blockSize: 4,
			want:      []byte{1, 2, 3, 4},
		},
		{
			name:      "valid padding 4",
			data:      []byte{9, 8, 7, 6, 5, 4, 0, 2},
			blockSize: 2,
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

			got, err := ANSIX923Unpad(tt.data, tt.blockSize)
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}

			testutil.AssertDeepEqual(t, got, tt.want)
		})
	}
}

func TestANSIX923Rountrip(t *testing.T) {
	testPadRountrip(t, "ANSIX923", ANSIX923Pad, ANSIX923Unpad)
}
