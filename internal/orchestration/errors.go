package orchestration

import "errors"

var (
	// ErrInvalidRequest is returned when Request validation fails.
	ErrInvalidRequest = errors.New("invalid request")
)
