package overlap

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestAnyOverlap(t *testing.T) {
	buffer := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	tests := []struct {
		name string
		x    []byte
		y    []byte
		want bool
	}{
		{
			name: "nil 1",
			x:    nil,
			y:    []byte{0},
			want: false,
		},
		{
			name: "nil 2",
			x:    []byte{0},
			y:    nil,
			want: false,
		},
		{
			name: "empty",
			x:    []byte{},
			y:    []byte{},
			want: false,
		},
		{
			name: "distinct",
			x:    []byte{1, 2},
			y:    []byte{1, 2},
			want: false,
		},
		{
			name: "no overlap",
			x:    buffer[0:2],
			y:    buffer[2:],
			want: false,
		},
		{
			name: "overlap 1",
			x:    buffer,
			y:    buffer[2:],
			want: true,
		},
		{
			name: "overlap 2",
			x:    buffer[3:5],
			y:    buffer[2:],
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnyOverlap(tt.x, tt.y)
			testutil.AssertEqual(t, got, tt.want)
		})
	}
}

func TestInexactOverlap(t *testing.T) {
	buffer := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	tests := []struct {
		name string
		x    []byte
		y    []byte
		want bool
	}{
		{
			name: "nil 1",
			x:    nil,
			y:    []byte{0},
			want: false,
		},
		{
			name: "nil 2",
			x:    []byte{0},
			y:    nil,
			want: false,
		},
		{
			name: "empty",
			x:    []byte{},
			y:    []byte{},
			want: false,
		},
		{
			name: "distinct",
			x:    []byte{1, 2},
			y:    []byte{1, 2},
			want: false,
		},
		{
			name: "no overlap",
			x:    buffer[0:2],
			y:    buffer[2:],
			want: false,
		},
		{
			name: "complete overlap",
			x:    buffer[2:5],
			y:    buffer[2:],
			want: false,
		},
		{
			name: "inexact overlap",
			x:    buffer[3:5],
			y:    buffer[2:],
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InexactOverlap(tt.x, tt.y)
			testutil.AssertEqual(t, got, tt.want)
		})
	}
}
