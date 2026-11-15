// Package rando defines wrapped crypto/rand and IV utilities.
package rando

import (
	"crypto/rand"

	"github.com/cryptography-class/aes-des-manipulator/internal/counter"
)

// RandomBytes generates n random bytes.
// n must be non-negative.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return b
}

// IncrementCounter treats iv as big-endian integer and adds n to it.
// On overflow the iv wraps around to zero.
func IncrementCounter(iv []byte, n uint64) {
	counter.Increment(iv, n)
}
