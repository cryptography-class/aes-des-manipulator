package des

import (
	std "crypto/des"
	"testing"
)

func BenchmarkCryptoNewDES(b *testing.B) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}

	b.ReportAllocs()
	for b.Loop() {
		_, err := std.NewCipher(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCustomNewDES(b *testing.B) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}

	b.ReportAllocs()
	for b.Loop() {
		_, err := NewDES(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoDESEncrypt(b *testing.B) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	src := []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}
	dst := make([]byte, blockSize)

	d, err := std.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		d.Encrypt(dst, src)
	}
}

// before precomputed lookup:
// BenchmarkCustomDESEncrypt-8       559311              2045 ns/op               0 B/op          0 allocs/op
// after precomputed lookup:
// BenchmarkCustomDESEncrypt-8      1000000              1160 ns/op               0 B/op          0 allocs/op
func BenchmarkCustomDESEncrypt(b *testing.B) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	src := []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}
	dst := make([]byte, blockSize)

	d, err := NewDES(key)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		d.Encrypt(dst, src)
	}
}

func BenchmarkCryptoDESDecrypt(b *testing.B) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	src := []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}
	dst := make([]byte, blockSize)

	d, err := std.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		d.Decrypt(dst, src)
	}
}

// before precomputed lookup:
// BenchmarkCustomDESDecrypt-8       576188              2038 ns/op               0 B/op          0 allocs/op
// after precomputed lookup:
// BenchmarkCustomDESDecrypt-8       995337              1168 ns/op               0 B/op          0 allocs/op
func BenchmarkCustomDESDecrypt(b *testing.B) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	src := []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}
	dst := make([]byte, blockSize)

	d, err := NewDES(key)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		d.Decrypt(dst, src)
	}
}

// before precomputed lookup:
// BenchmarkFeistelNetwork-8         617511              1879 ns/op               0 B/op          0 allocs/op
// after precomputed lookup:
// BenchmarkFeistelNetwork-8        1203723               996.3 ns/op             0 B/op          0 allocs/op
func BenchmarkFeistelNetwork(b *testing.B) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	in := uint64(0) << 32
	subkey := uint64(0) << 48

	d, err := NewDES(key)
	if err != nil {
		b.Fatal(err)
	}

	des, ok := d.(*des)
	if !ok {
		b.Fatal("NewDES() did not return a des")
	}

	b.ReportAllocs()
	for b.Loop() {
		for range 16 {
			_ = des.feistelNetwork(in, subkey)
		}
	}
}
