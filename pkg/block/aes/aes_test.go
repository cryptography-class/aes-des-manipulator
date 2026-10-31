package aes

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestNewAES128(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		want    [4 * (rounds128 + 1)]uint32
		wantErr bool
	}{
		{
			// source: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
			name: "valid 1",
			key:  []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
			want: [4 * (rounds128 + 1)]uint32{
				0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, // initial key
				0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, // round 1  (w4-w7)
				0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, // round 2  (w8-w11)
				0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, // round 3  (w12-w15)
				0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, // round 4  (w16-w19)
				0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc, // round 5  (w20-w23)
				0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, // round 6  (w24-w27)
				0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, // round 7  (w28-w31)
				0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f, // round 8  (w32-w35)
				0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, // round 9  (w36-w39)
				0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6, // round 10 (w40-w43)
			},
		},
		{
			name:    "invalid key length 1",
			key:     nil,
			wantErr: true,
		},
		{
			name:    "invalid key length 2",
			key:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantErr: true,
		},
		{
			name:    "invalid key length 3",
			key:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAES(tt.key)
			testutil.AssertNilError(t, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			a, ok := got.(*aes)
			if !ok {
				t.Fatalf("NewAES() did not return an aes")
			}
			testutil.AssertEqual(t, a.subkeys, tt.want)
		})
	}
}
