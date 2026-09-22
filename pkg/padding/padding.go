// Package padding defines different padding schemes.
package padding

import "crypto/subtle"

// PadFunc pads data to a multiple of blockSize.
type PadFunc func(data []byte, blockSize int) []byte

// UnpadFunc reverses PadFunc.
// It returns an error on invalid padding.
type UnpadFunc func(data []byte, blockSize int) ([]byte, error)

// equalityByte returns the byte used in validateConstantTime to compare the padding data to.
// Each padding scheme should define its own equalityByte.
type equalityByte func([]byte, int) byte

// validateConstantTime validate an arbitrary padding scheme in constant time
// to avoid an Oracle Padding Attack.
func validateConstantTime(data []byte, blockSize int, padLength int, b equalityByte) bool {
	valid := subtle.ConstantTimeLessOrEq(1, padLength) & subtle.ConstantTimeLessOrEq(padLength, blockSize)

	block := data[len(data)-blockSize:]
	var bad int
	for i := 1; i <= blockSize; i++ {
		inPad := subtle.ConstantTimeLessOrEq(i, padLength)
		differs := 1 ^ subtle.ConstantTimeByteEq(block[blockSize-i], b(block, i))
		bad |= inPad & differs
	}
	valid &= 1 ^ bad

	return valid == 1
}
