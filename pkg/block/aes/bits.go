package aes

import "math/bits"

// subWord substitutes the provided 32-bit word via sbox.
func subWord(in uint32) uint32 {
	var out uint32
	out |= uint32(sbox[(in>>24)&0xff]) << 24
	out |= uint32(sbox[(in>>16)&0xff]) << 16
	out |= uint32(sbox[(in>>8)&0xff]) << 8
	out |= uint32(sbox[in&0xff])

	return out
}

// mixColumn applies the MinColumns matrix to one column.
func mixColumn(w uint32) uint32 {
	r8 := bits.RotateLeft32(w, 8)
	r16 := bits.RotateLeft32(w, 16)
	r24 := bits.RotateLeft32(w, 24)

	return xtime(w^r8) ^ r8 ^ r16 ^ r24
}

// xtime multiplies each of the 4 bytes of in by 0x02 in GF(2^8).
func xtime(in uint32) uint32 {
	hi := (in >> 7) & 0x01010101
	lo := (in & 0x7f7f7f7f) << 1

	return lo ^ (hi * 0x1b)
}
