// Package orchestration defines the processing layer that handles the core logic.
package orchestration

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
)

// Request is the request processed by Orchestrator.
type Request struct {
	Action        Action
	Mode          Mode
	Cipher        block.Cipher
	Padder        *padding.Padder // nil for CTR
	IV            []byte
	Src           Source
	Dst           Sink
	HeaderLength  int64
	TrailerLength int64
	Options
}

// validate checks Request for programmer and input errors.
// It errors on invalid input.
// It panics on programmer errors.
func (r *Request) validate() error {
	// panics on programmer errors
	if r.Cipher == nil || r.Src == nil || r.Dst == nil {
		panic("orchestration: Request requires Cipher, Src and Dst")
	}

	switch r.Action {
	case Encrypt, Decrypt:
	default:
		panic(fmt.Sprintf("orchestration: unknown action %s", r.Action))
	}

	switch r.Mode {
	case ECB, CBC:
		if r.Padder == nil {
			panic(fmt.Sprintf("orchestration: padder required for %s", r.Mode))
		}

	case CTR:
		if r.Padder != nil {
			panic("orchestration: CTR does not take a padder")
		}

	default:
		panic(fmt.Sprintf("orchestration: unknown mode %s", r.Mode))
	}

	// actual input errors
	blockSize := int64(r.Cipher.BlockSize())
	var errs []error

	if r.HeaderLength < 0 || r.TrailerLength < 0 || r.HeaderLength > r.Src.Size() || r.TrailerLength > r.Src.Size()+r.HeaderLength {
		errs = append(errs, fmt.Errorf("header (%d) and trailer (%d) do not fit in a %d byte file",
			r.HeaderLength, r.TrailerLength, r.Src.Size()))
	}

	if r.Mode != ECB && int64(len(r.IV)) != blockSize {
		errs = append(errs, fmt.Errorf("IV must be %d bytes, got %d", blockSize, len(r.IV)))
	}

	if r.ChunkSizeBytes <= 0 || r.ChunkSizeBytes%blockSize != 0 {
		errs = append(errs, fmt.Errorf("chunk size %d must be a positive multiple of %d", r.ChunkSizeBytes, blockSize))
	}

	if r.Goroutines < 1 {
		errs = append(errs, fmt.Errorf("goroutines must be at least 1, got %d", r.Goroutines))
	}

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}

	return nil
}

type Orchestrator struct{}

// Process orchestrates a Runner to process the Request.
func (o *Orchestrator) Process(ctx context.Context, req *Request) error {
	if err := req.validate(); err != nil {
		return err
	}

	if ctx.Err() != nil {
		return fmt.Errorf("process: %w", ctx.Err())
	}

	runner, err := newRunner(runnerConfig{
		mode:   req.Mode,
		action: req.Action,
		cipher: req.Cipher,
		padder: req.Padder,
		iv:     req.IV,
	})
	if err != nil {
		return fmt.Errorf("process: failed to create a new runner: %w", err)
	}

	payloadSize := req.Src.Size() - req.HeaderLength - req.TrailerLength
	payload := io.NewSectionReader(req.Src, req.HeaderLength, payloadSize)

	outSize, err := runner.PreRun(payload, payloadSize)
	if err != nil {
		return fmt.Errorf("process: prerun failed: %w", err)
	}

	if err := req.Dst.Truncate(req.HeaderLength + outSize + req.TrailerLength); err != nil {
		return fmt.Errorf("process: truncate: %w", err)
	}

	// copy the header
	if err := copyRegion(req.Dst, 0, req.Src, 0, req.HeaderLength); err != nil {
		return fmt.Errorf("process: copy header: %w", err)
	}

	// copy the trailer
	if err := copyRegion(req.Dst, req.HeaderLength+outSize, req.Src, req.HeaderLength+payloadSize, req.TrailerLength); err != nil {
		return fmt.Errorf("process: copy trailer: %w", err)
	}

	j := &job{
		src:  payload,
		dst:  io.NewOffsetWriter(req.Dst, req.HeaderLength),
		size: payloadSize,
	}
	if err := runner.Run(ctx, j, req.Options); err != nil {
		return fmt.Errorf("process: run failed: %w", err)
	}

	return nil
}
