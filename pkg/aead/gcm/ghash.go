package gcm

import "encoding/binary"

// ghashPhase is the current phase of ghash.
type ghashPhase uint8

const (
	phaseAAD ghashPhase = iota
	phaseCiphertext
	phaseDone
)

// ghash is a streaming implementation of GHASH.
//
// Spec: https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf.
type ghash struct {
	// h is the key of ghash.
	h fieldElement

	// y is the current running sum of ghash.
	y fieldElement

	// buffer stores leftover bytes of AAD/Ciphertext.
	// It is flushed when changing phases.
	buffer [16]byte

	// n is the number of bytes currently in buffer.
	n int

	// aadLength is the number of bytes of
	// additional data ingested.
	aadLength uint64

	// ciphertextLength is the number of bytes of
	// ciphertext ingested.
	ciphertextLength uint64

	// phase is the current phase of ghash:
	// additional data, ciphertext or done.
	phase ghashPhase
}

// newGhash initializes a new ghash instance with the provided key.
func newGhash(h [16]byte) *ghash {
	return &ghash{
		h: newFieldElement(h),
	}
}

// writeAAD ingests additional data.
//
// It panics when called after writeCiphertext or sum.
func (g *ghash) writeAAD(data []byte) {
	switch g.phase {
	case phaseCiphertext:
		panic("ghash: writing additional data after ciphertext")

	case phaseDone:
		panic("ghash: writing additional data after ghash is already used")

	default:
	}

	g.aadLength += uint64(len(data))
	g.write(data)
}

// writeCiphertext ingests ciphertext.
//
// It panics when called after sum.
func (g *ghash) writeCiphertext(ciphertext []byte) {
	switch g.phase {
	case phaseAAD:
		g.phase = phaseCiphertext
		g.flush()

	case phaseDone:
		panic("ghash: writing ciphertext after ghash is already used")

	default:
	}

	g.ciphertextLength += uint64(len(ciphertext))
	g.write(ciphertext)
}

// sum produces GHASH(H, A, C).
// Instance of ghash should be discarded after using sum.
//
// It panics on a second use.
func (g *ghash) sum() [16]byte {
	if g.phase == phaseDone {
		panic("ghash: hashing after ghash is already used")
	}

	g.phase = phaseDone
	g.flush()

	lengthBlock := fieldElement{
		high: g.aadLength * 8,
		low:  g.ciphertextLength * 8,
	}

	g.y = mul(xor(g.y, lengthBlock, 0xFFFFFFFFFFFFFFFF), g.h)

	sum := [16]byte{}
	binary.BigEndian.PutUint64(sum[:8], g.y.high)
	binary.BigEndian.PutUint64(sum[8:], g.y.low)
	return sum
}

// write ingests any data.
func (g *ghash) write(data []byte) {
	if g.n > 0 {
		k := copy(g.buffer[g.n:], data)
		g.n += k
		data = data[k:]

		if g.n < 16 {
			return
		}

		g.absorb(g.buffer)
		g.n = 0
	}

	for len(data) >= 16 {
		g.absorb([16]byte(data[:16]))
		data = data[16:]
	}

	g.n = copy(g.buffer[:], data)
}

// absorb adds block to the running sum y.
func (g *ghash) absorb(block [16]byte) {
	g.y = mul(xor(g.y, newFieldElement(block), 0xFFFFFFFFFFFFFFFF), g.h)
}

// flush pads the leftover bytes in buffer and absorbs them
// if the buffer is not empty.
func (g *ghash) flush() {
	if g.n != 0 {
		clear(g.buffer[g.n:])
		g.absorb(g.buffer)
		g.n = 0
	}
}
