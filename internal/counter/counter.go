package counter

// Increment treats counter as big-endian integer and adds n to it.
// On overflow the counter wraps around to zero.
func Increment(counter []byte, n uint64) {
	carry := n
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(counter[i]) + (carry & 0xFF)
		counter[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
}
