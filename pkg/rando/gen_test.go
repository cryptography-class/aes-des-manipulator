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

func TestIncrementCounter(t *testing.T) {
	tests := []struct {
		name    string
		counter []byte
		n       uint64
		want    []byte
	}{
		{
			name:    "normal",
			counter: []byte{1},
			n:       23,
			want:    []byte{24},
		},
		{
			name:    "wrap-around 1",
			counter: []byte{255},
			n:       1,
			want:    []byte{0},
		},
		{
			name:    "wrap-around 2",
			counter: []byte{255},
			n:       257,
			want:    []byte{0},
		},
		{
			name:    "wrap-around 3",
			counter: []byte{255},
			n:       2,
			want:    []byte{1},
		},
		{
			name:    "carry 1",
			counter: []byte{0, 255},
			n:       1,
			want:    []byte{1, 0},
		},
		{
			name:    "carry 2",
			counter: []byte{0, 255, 255},
			n:       1,
			want:    []byte{1, 0, 0},
		},
		{
			name:    "carry 3",
			counter: []byte{0, 0, 250},
			n:       262,
			want:    []byte{0, 2, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			IncrementCounter(tt.counter, tt.n)
			testutil.AssertDeepEqual(t, tt.counter, tt.want)
		})
	}
}
