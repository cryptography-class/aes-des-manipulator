package gcm

import (
	"crypto/rand"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func loadFieldElement(t *testing.T, h string) fieldElement {
	t.Helper()

	return newFieldElement([16]byte(testutil.MustHex(t, h)))
}

func TestMul(t *testing.T) {
	tests := []struct {
		name string
		x    fieldElement
		y    fieldElement
		want fieldElement
	}{
		{
			name: "times 0",
			x:    loadFieldElement(t, "66e94bd4ef8a2c3b884cfa59ca342b2e"),
			y:    loadFieldElement(t, "00000000000000000000000000000000"),
			want: loadFieldElement(t, "00000000000000000000000000000000"),
		},
		{
			name: "times 1",
			x:    loadFieldElement(t, "66e94bd4ef8a2c3b884cfa59ca342b2e"),
			y:    loadFieldElement(t, "80000000000000000000000000000000"),
			want: loadFieldElement(t, "66e94bd4ef8a2c3b884cfa59ca342b2e"),
		},
		{
			name: "random 1",
			x:    loadFieldElement(t, "f38b2ffc80a4df5a51c9bc701e7ea419"),
			y:    loadFieldElement(t, "f3f49249dc28ff90a5aec7978306d03b"),
			want: loadFieldElement(t, "1b5f58e6bb3ebc82d3d2a2f0b2301a06"),
		},
		{
			name: "random 2",
			x:    loadFieldElement(t, "e512148239292d22e255accb1a466884"),
			y:    loadFieldElement(t, "6bad6be28e7aa6e99f19950499dd251d"),
			want: loadFieldElement(t, "fd6ed81236db22b5f844746c44a221fd"),
		},
		{
			name: "random 3",
			x:    loadFieldElement(t, "d7a7a3cc8c3d5f169293de8fc88b2875"),
			y:    loadFieldElement(t, "7dabe929c4a334bfc6cd75e9bb049a79"),
			want: loadFieldElement(t, "0e230eae971776c7cb8f69a78a9a339d"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AssertDeepEqual(t, mul(tt.x, tt.y), tt.want)
		})
	}
}

func TestMulCommutativity(t *testing.T) {
	for range 255 {
		x := [16]byte{}
		_, _ = rand.Read(x[:])

		y := [16]byte{}
		_, _ = rand.Read(y[:])

		a := newFieldElement(x)
		b := newFieldElement(y)

		testutil.AssertDeepEqual(t, mul(a, b), mul(b, a))
	}
}
