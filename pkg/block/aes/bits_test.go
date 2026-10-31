package aes

import (
	"encoding/binary"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestSubWord(t *testing.T) {
	tests := []struct {
		name string
		in   uint32
		want uint32
	}{
		{
			name: "valid 1",
			in:   binary.BigEndian.Uint32([]byte{0xcf, 0x4f, 0x3c, 0x09}),
			want: binary.BigEndian.Uint32([]byte{0x8a, 0x84, 0xeb, 0x01}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AssertEqual(t, subWord(tt.in), tt.want)
		})
	}
}
