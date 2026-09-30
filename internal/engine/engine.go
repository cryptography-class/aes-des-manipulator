package engine

// Action is a crypt action.
type Action int

const (
	// Encrypt represents an encrypt action.
	Encrypt Action = iota
	// Decrypt represents a decrypt action.
	Decrypt
)

// Engine is a structure that defines concurrent operations
// for file processing for different modes.
type Engine struct {
	goroutines     int
	chunkSizeBytes int64
}

// NewEngine initializes a new engine with the provided
// amount of goroutines and chunk size in bytes.
// It panics when the amount of goroutines or the chunk size is non-positive.
func NewEngine(goroutines int, chunkSizeBytes int64) *Engine {
	if goroutines < 1 {
		panic("engine: goroutines must be at least 1")
	}

	if chunkSizeBytes < 1 {
		panic("engine: chunkSizeBytes must be at least 1")
	}

	return &Engine{
		goroutines:     goroutines,
		chunkSizeBytes: chunkSizeBytes,
	}
}
