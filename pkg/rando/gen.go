// Package rando defines wrapped crypto/rand and IV utilities.
package rando

import "crypto/rand"

// RandomBytes generates n random bytes.
// n must be non-negative.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return b
}

// IncrementCounter treats counter as big-endian integer and adds n to it.
// On overflow the counter wraps around to zero.
func IncrementCounter(counter []byte, n uint64) {
	carry := n
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(counter[i]) + (carry & 0xFF)
		counter[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
}
