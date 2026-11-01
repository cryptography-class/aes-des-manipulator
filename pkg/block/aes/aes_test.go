package aes

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestNewAES(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		enc     [4 * (rounds256 + 1)]uint32
		dec     [4 * (rounds256 + 1)]uint32
		wantErr bool
	}{
		{
			// source: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
			name: "KAT 1",
			key: []byte{
				0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
				0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
			},
			enc: [4 * (rounds256 + 1)]uint32{
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
			dec: [4 * (rounds256 + 1)]uint32{
				0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6, // round 10 (w40-w43)
				0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, // round 9  (w36-w39)
				0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f, // round 8  (w32-w35)
				0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, // round 7  (w28-w31)
				0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, // round 6  (w24-w27)
				0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc, // round 5  (w20-w23)
				0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, // round 4  (w16-w19)
				0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, // round 3  (w12-w15)
				0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, // round 2  (w8-w11)
				0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, // round 1  (w4-w7)
				0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, // initial key
			},
		},
		{
			// source: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
			name: "KAT 2",
			key: []byte{
				0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
				0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
			},
			enc: [4 * (rounds256 + 1)]uint32{
				0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, // round 0
				0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5, // round 1
				0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, // round 2
				0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, // round 3
				0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, // round 4
				0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6, // round 5
				0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, // round 6
				0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, // round 7
				0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3, // round 8
				0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, // round 9
				0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753, // round 10
				0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5, // round 11
				0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202, // round 12
			},
			dec: [4 * (rounds256 + 1)]uint32{
				0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202, // round 12
				0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5, // round 11
				0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753, // round 10
				0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, // round 9
				0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3, // round 8
				0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, // round 7
				0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, // round 6
				0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6, // round 5
				0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, // round 4
				0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, // round 3
				0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, // round 2
				0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5, // round 1
				0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, // round 0
			},
		},
		{
			// source: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
			name: "KAT 3",
			key: []byte{
				0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
				0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
			},
			enc: [4 * (rounds256 + 1)]uint32{
				0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, // round 0
				0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4, // round 1
				0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, // round 2
				0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, // round 3
				0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, // round 4
				0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3, // round 5
				0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, // round 6
				0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, // round 7
				0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80, // round 8
				0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, // round 9
				0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, // round 10
				0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, // round 11
				0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, // round 12
				0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d, // round 13
				0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e, // round 14
			},
			dec: [4 * (rounds256 + 1)]uint32{
				0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e, // round 14
				0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d, // round 13
				0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, // round 12
				0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, // round 11
				0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, // round 10
				0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, // round 9
				0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80, // round 8
				0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, // round 7
				0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, // round 6
				0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3, // round 5
				0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, // round 4
				0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, // round 3
				0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, // round 2
				0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4, // round 1
				0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, // round 0
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
		{
			name: "invalid key length 4",
			key: []byte{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				1, 2, 3, 4, 5, 6, 7,
			},
			wantErr: true,
		},
		{
			name: "invalid key length 5",
			key: []byte{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				1, 2, 3, 4, 5, 6, 7, 8, 9,
			},
			wantErr: true,
		},
		{
			name: "invalid key length 6",
			key: []byte{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			},
			wantErr: true,
		},
		{
			name: "invalid key length 7",
			key: []byte{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
			},
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
			testutil.AssertEqual(t, a.enc, tt.enc)
			testutil.AssertEqual(t, a.dec, tt.dec)
		})
	}
}

func TestBlockSize(t *testing.T) {
	t.Run("block size", func(t *testing.T) {
		var a aes
		testutil.AssertEqual(t, a.BlockSize(), BlockSize)
		testutil.AssertEqual(t, a.BlockSize(), 16)
	})
}
