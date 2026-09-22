package padding

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func testPadRountrip(t *testing.T, name string, pad PadFunc, unpad UnpadFunc) {
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
			name:      "valid padding 2",
			data:      []byte{1, 3, 2, 2},
			blockSize: 4,
		},
		{
			name:      "valid padding 3",
			data:      []byte{1, 3, 2, 2},
			blockSize: 2,
		},
		{
			name:      "valid padding 4",
			data:      []byte{1, 2},
			blockSize: 3,
		},
		{
			name:      "valid padding 5",
			data:      []byte{},
			blockSize: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pad(tt.data, tt.blockSize)
			got, err := unpad(padded, tt.blockSize)
			if err != nil {
				t.Fatalf("%sUnpad() error = %v", name, err)
			}

			testutil.AssertDeepEqual(t, got, tt.data)
		})
	}
}
