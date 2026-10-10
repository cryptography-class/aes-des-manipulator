package core

import "errors"

// TODO: REFACTOR core BEFORE THE RELEASE
// THIS ERROR HANDING IS A MESS THAT NEEDS TO BE RESOLVED

var (
	// ErrInvalidRequest is returned when Request validation fails.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrInvalidData is returned when a runner encounters an issue in the source.
	ErrInvalidData = errors.New("invalid data")

	// ErrInvalidPadding is returned when a runner encounters an issue in padding.
	ErrInvalidPadding = errors.New("invalid padding")
)
