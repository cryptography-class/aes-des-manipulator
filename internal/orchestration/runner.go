package orchestration

import (
	"context"
	"fmt"
	"io"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
)

// Options is a Runner.Run concurrency configuration.
type Options struct {
	ChunkSizeBytes int64
	Goroutines     int
}

// Runner is a logical processor of a Mode.
type Runner interface {
	// PreRun validates padding with fast-failing for modes that require it
	// and computes the output size.
	PreRun(src io.ReaderAt, size int64) (outSize int64, err error)

	// Run processes the provided job in a concurrent manner defined by the mode.
	// opts define the amount of goroutines used and the size of the read chunks.
	Run(ctx context.Context, job *job, opts Options) error
}

// job is a single entity processed by Runner.Run.
type job struct {
	src io.ReaderAt
	dst io.WriterAt
	// size is the amount of raw bytes without header or trailer.
	size int64
}

// runnerConfig is the configuration struct for a Runner.
type runnerConfig struct {
	mode   Mode
	action Action
	cipher block.Cipher
	padder *padding.Padder
	iv     []byte
}

// newRunner builds the runner for the given mode and action.
func newRunner(cfg runnerConfig) (Runner, error) {
	switch cfg.mode {
	case ECB:
		return newECBRunner(cfg.cipher, cfg.padder, cfg.action)

	case CBC:
		return newCBCRunner(cfg.cipher, cfg.padder, cfg.iv, cfg.action)

	case CTR:
		return newCTRRunner(cfg.cipher, cfg.iv)

	default:
		panic(fmt.Sprintf("newRunner: unknown mode %s", cfg.mode))
	}
}
