package padding

import "bytes"

// PKCS7Pad applies the PKCS#7 padding scheme to data with the provided blockSize.
// It appends a full extra block when len(data) == blockSize.
// It panics when blockSize is not in (0; 255].
func PKCS7Pad(data []byte, blockSize int) []byte {
	if blockSize <= 0 || blockSize > 255 {
		panic("padding: blockSize must be between 1 and 255")
	}

	padLength := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data), len(data)+padLength)
	copy(padded, data)

	return append(padded, bytes.Repeat([]byte{byte(padLength)}, padLength)...)
}

// PKCS7Unpad verifies and removes the PKCS#7 padding scheme from the provided data.
// It errors on an empty data or when the padding is invalid.
func PKCS7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, ErrInvalidPadding
	}

	// verify the padding is valid in constant time
	var mismatch byte
	for _, b := range data[len(data)-padding:] {
		mismatch |= b ^ byte(padding)
	}

	if mismatch != 0 {
		return nil, ErrInvalidPadding
	}

	return data[:len(data)-padding], nil
}
