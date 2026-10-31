package aes

// subWord substitutes the provided 32-bit word via sbox.
func subWord(in uint32) uint32 {
	var out uint32
	out |= uint32(sbox[(in>>24)&0xff]) << 24
	out |= uint32(sbox[(in>>16)&0xff]) << 16
	out |= uint32(sbox[(in>>8)&0xff]) << 8
	out |= uint32(sbox[in&0xff])

	return out
}
