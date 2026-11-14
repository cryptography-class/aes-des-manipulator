package aead

import "errors"

var (
	// ErrLengthMismatch is returned when dst and src have different lengths.
	ErrLengthMismatch = errors.New("aead: dst and src length mismatch")

	// ErrInexactOverlap is returned when dst and src partially overlap.
	ErrInexactOverlap = errors.New("aead: dst and src partially overlap")

	// ErrTooMuchData is returned when aead reaches the limit of possible encrypted data.
	ErrTooMuchData = errors.New("aead: too much data")

	// ErrInvalidAuthentication is returned when the tag is invalid.
	ErrInvalidAuthentication = errors.New("aead: invalid authentication")
)
