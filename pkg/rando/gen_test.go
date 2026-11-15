package rando

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestRandomBytes(t *testing.T) {
	tests := []struct {
		name      string
		n         int
		wantPanic bool
	}{
		{
			name: "valid",
			n:    10,
		},
		{
			name: "zero",
			n:    0,
		},
		{
			name:      "negative",
			n:         -1,
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			_ = RandomBytes(tt.n)
		})
	}
}
