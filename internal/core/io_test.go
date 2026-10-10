package core

import (
	"bytes"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestCopyRegion(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		dstOffset int64
		srcOffset int64
		n         int64
		want      string
	}{
		{
			name:      "copy header",
			src:       "hello world",
			dstOffset: 0,
			srcOffset: 0,
			n:         5,
			want:      "hello",
		},
		{
			name:      "copy region",
			src:       "hello world",
			dstOffset: 0,
			srcOffset: 6,
			n:         5,
			want:      "world",
		},
		{
			name:      "copy into offset",
			src:       "hello world",
			dstOffset: 5,
			srcOffset: 0,
			n:         5,
			want:      "\x00\x00\x00\x00\x00hello",
		},
		{
			name:      "zero bytes",
			src:       "hello",
			dstOffset: 0,
			srcOffset: 0,
			n:         0,
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := bytes.NewReader([]byte(tt.src))
			dst := &testutil.TestWriterAt{}

			if err := copyRegion(dst, tt.dstOffset, src, tt.srcOffset, tt.n); err != nil {
				t.Fatalf("copyRegion(): %v", err)
			}

			testutil.AssertBytesEqual(t, dst.Data, []byte(tt.want))
		})
	}
}
