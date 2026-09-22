package padding

import "errors"

var (
	// ErrEmptyInput is returned on an empty block input.
	ErrEmptyInput = errors.New("padding: data is empty")

	// ErrInvalidPadding is returned during unpad when the padded block has invalid padding
	// or violates the schemes padding contract.
	ErrInvalidPadding = errors.New("padding: invalid padding")
)
