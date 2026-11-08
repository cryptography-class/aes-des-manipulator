package aead

import "encoding/binary"

// fieldElement is polynomial in GF(2^128).
// It is represented by two uint64 values:
//
//	H63_H62_H61...H0_L63_L62...L0
//	0_1_2...63_64_65...127
type fieldElement struct {
	// high represents bytes 0...7 of the field element.
	//
	// Bit mapping:
	// 	leftmost bit of high (63) -> bit (0) of the element
	//	rightmost bit of high (0) -> bit (63) of the element
	high uint64

	// low represents bytes 8...15 of the field element.
	//
	// Bit mapping:
	// 	leftmost bit of low (63) -> bit (64) of the element
	//	rightmost bit of low (0) -> bit (127) of the element
	low uint64
}

// newFieldElement loads 16 bytes into an element of GF(2^128).
func newFieldElement(block [16]byte) fieldElement {
	return fieldElement{
		high: binary.BigEndian.Uint64(block[0:8]),
		low:  binary.BigEndian.Uint64(block[8:16]),
	}
}

// xor adds two elements of GF(2^128).
func xor(a, b fieldElement) fieldElement {
	return fieldElement{
		high: a.high ^ b.high,
		low:  a.low ^ b.low,
	}
}

// bitSet checks whether the bit at position is set.
func (e *fieldElement) bitSet(position int) bool {
	if position > 63 {
		return ((e.low >> (127 - position)) & 1) == 1
	}

	return ((e.high >> (63 - position)) & 1) == 1
}

// mulX multiplies an element by x in GF(2^128).
func mulX(e fieldElement) fieldElement {
	fold := (e.low & 1) == 1

	high := e.high >> 1

	// bit 0 of high becomes bit 63 of low after the shift
	low := (e.low >> 1) | (e.high << 63)

	if fold {
		high = high ^ (0xE1 << 56)
	}

	return fieldElement{
		high: high,
		low:  low,
	}
}

// mul multiplies two elements of GF(2^128).
func mul(x, y fieldElement) fieldElement {
	z := fieldElement{}
	v := y

	for i := range 128 {
		if x.bitSet(i) {
			z = xor(z, v)
		}

		v = mulX(v)
	}

	return z
}
