package bits

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestGetBit(t *testing.T) {
	tests := []struct {
		name      string
		x         uint64
		length    int
		position  int
		want      uint64
		wantPanic bool
	}{
		{
			name:     "position 1",
			x:        0b1011,
			length:   4,
			position: 1,
			want:     0b1,
		},
		{
			name:     "position 2",
			x:        0b1011,
			length:   4,
			position: 2,
			want:     0b0,
		},
		{
			name:     "position 3",
			x:        0b1011,
			length:   4,
			position: 3,
			want:     0b1,
		},
		{
			name:     "position 4",
			x:        0b1011,
			length:   4,
			position: 4,
			want:     0b1,
		},
		{
			// silently returns 0
			name:     "position 0",
			x:        0b1011,
			length:   4,
			position: 0,
			want:     0b0,
		},
		{
			// silently returns 0
			name:     "position < 0",
			x:        0b1011,
			length:   4,
			position: -1,
			want:     0b0,
		},
		{
			// shifting by a negative amount
			name:      "position > length",
			x:         0b1011,
			length:    4,
			position:  5,
			wantPanic: true,
		},
		{
			// shifting by a negative amount
			name:      "length <= 0",
			x:         0b1011,
			length:    0,
			position:  1,
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			got := GetBit(tt.x, tt.length, tt.position)
			testutil.AssertEqual(t, got, tt.want)
		})
	}
}

func TestPermute(t *testing.T) {
	tests := []struct {
		name        string
		x           uint64
		length      int
		permutation []int
		want        uint64
		wantPanic   bool
	}{
		{
			name:        "swap",
			x:           0b10,
			length:      2,
			permutation: []int{2, 1},
			want:        0b01,
		},
		{
			name:        "initial",
			x:           0b11111,
			length:      5,
			permutation: []int{1, 2, 3, 4, 5},
			want:        0b11111,
		},
		{
			name:        "negative position in permutation",
			x:           0b11,
			length:      2,
			permutation: []int{-1, 1},
			want:        0b01,
		},
		{
			name:        "duplicate position in permutation",
			x:           0b101,
			length:      3,
			permutation: []int{1, 1, 2},
			want:        0b110,
		},
		{
			// shifting by a negative amount
			name:        "permutation entry exceeds length",
			x:           0b101,
			length:      3,
			permutation: []int{1, 3, 2, 5, 6},
			wantPanic:   true,
		},
		{
			name:        "empty permutation",
			x:           0b1011,
			length:      4,
			permutation: []int{},
			want:        0b0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			got := Permute(tt.x, tt.length, tt.permutation)
			testutil.AssertEqual(t, got, tt.want)
		})
	}

	t.Run("output truncates for narrow int type", func(t *testing.T) {
		x := uint8(0b10)
		length := 2
		// silently truncates
		permutation := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

		defer func() {
			testutil.AssertPanic(t, recover(), false)
		}()

		got := Permute(x, length, permutation)
		testutil.AssertEqual(t, got, 0b11111111)
	})
}

func TestLeftRotate(t *testing.T) {
	tests := []struct {
		name      string
		x         uint64
		length    int
		shift     int
		want      uint64
		wantPanic bool
	}{
		{
			name:   "shift 0",
			x:      0b1011,
			length: 4,
			shift:  0,
			want:   0b1011,
		},
		{
			name:   "shift 1",
			x:      0b1011,
			length: 4,
			shift:  1,
			want:   0b0111,
		},
		{
			name:   "shift 2",
			x:      0b1011,
			length: 4,
			shift:  2,
			want:   0b1110,
		},
		{
			name:   "shift 3",
			x:      0b1011,
			length: 4,
			shift:  3,
			want:   0b1101,
		},
		{
			name:   "shift 4",
			x:      0b1011,
			length: 4,
			shift:  4,
			want:   0b1011,
		},
		{
			// shifting by a negative amount
			name:      "shift > length",
			x:         0b1011,
			length:    4,
			shift:     5,
			wantPanic: true,
		},
		{
			// shifting by a negative amount
			name:      "negative shift",
			x:         0b1011,
			length:    4,
			shift:     -1,
			wantPanic: true,
		},
		{
			// shifting by a negative amount
			name:      "negative length",
			x:         0b1011,
			length:    -1,
			shift:     1,
			wantPanic: true,
		},
		{
			// silently truncates
			name:   "length mismatch",
			x:      0b1011,
			length: 3,
			shift:  1,
			want:   0b110,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			got := LeftRotate(tt.x, tt.length, tt.shift)
			testutil.AssertEqual(t, got, tt.want)
		})
	}
}
