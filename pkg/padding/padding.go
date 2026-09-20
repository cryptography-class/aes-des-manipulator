// Package padding defines different padding schemes.
package padding

// PadFunc pads data to a multiple of blockSize.
type PadFunc func(data []byte, blockSize int) []byte

// UnpadFunc reverses PadFunc.
// It returns an error on invalid padding.
type UnpadFunc func(data []byte) ([]byte, error)
