package padding

// PKCS7Pad applies the PKCS#7 padding scheme to data with the provided blockSize.
// It appends a full extra block when len(data) % blockSize == 0.
// It panics when blockSize is not in (0; 255].
func PKCS7Pad(data []byte, blockSize int) []byte {
	// it's a programmer error and not a data error, so we panic
	if blockSize <= 0 || blockSize > 255 {
		panic("padding: blockSize must be between 1 and 255")
	}

	padLength := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padLength)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLength)
	}

	return padded
}

// PKCS7Unpad verifies and removes the PKCS#7 padding scheme from the provided data.
// It errors on an empty data or when the padding is invalid.
// It panics when blockSize is not in (0; 255].
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	// panic is deliberate here and mimics the Pad function
	// it's a programmer error and not a data error
	if blockSize <= 0 || blockSize > 255 {
		panic("padding: blockSize must be between 1 and 255")
	}

	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	if len(data)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}

	padLength := int(data[len(data)-1])
	if ok := validateConstantTime(data, blockSize, padLength, func(_ []byte, _ int) byte {
		return byte(padLength)
	}); !ok {
		return nil, ErrInvalidPadding
	}

	return data[:len(data)-padLength], nil
}
