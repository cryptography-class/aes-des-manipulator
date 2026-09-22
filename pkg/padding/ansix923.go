package padding

// ANSIX923Pad applies the ANSIX9.23 padding scheme to data with the provided blockSize.
// It appends a full extra block when len(data) % blockSize == 0.
// It panics when blockSize is not in (0; 255].
func ANSIX923Pad(data []byte, blockSize int) []byte {
	// it's a programmer error and not a data error, so we panic
	if blockSize <= 0 || blockSize > 255 {
		panic("padding: blockSize must be between 1 and 255")
	}

	padLength := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padLength)
	copy(padded, data)
	padded[len(padded)-1] = byte(padLength)

	return padded
}

// ANSIX923Unpad verifies and removes the ANSIX9.23 padding scheme from the provided data.
// It panics when blockSize is not in (0; 255].
// It errors on an empty data or when the padding is invalid.
func ANSIX923Unpad(data []byte, blockSize int) ([]byte, error) {
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
	if ok := validateConstantTime(data, blockSize, padLength, func(_ []byte, i int) byte {
		if i == 1 {
			return byte(padLength)
		}
		return 0
	}); !ok {
		return nil, ErrInvalidPadding
	}

	return data[:len(data)-padLength], nil
}
