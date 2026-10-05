package orchestration

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/mode"
	"github.com/cryptography-class/aes-des-manipulator/pkg/rando"
	"golang.org/x/sync/errgroup"
)

// ctrRunner implements Runner.
type ctrRunner struct {
	cipher         block.Cipher
	initialCounter []byte
}

// newCTRRunner initializes a new ctrRunner with the provided cipher and counter.
// It errors when the length of the initialCounter does not match cipher's blocksize.
func newCTRRunner(cipher block.Cipher, counter []byte) (*ctrRunner, error) {
	if len(counter) != cipher.BlockSize() {
		return nil, fmt.Errorf("initialCounter length must be %d bytes", cipher.BlockSize())
	}

	return &ctrRunner{
		cipher:         cipher,
		initialCounter: bytes.Clone(counter),
	}, nil
}

// PreRun implements Runner.
//
// CTR does not require any padding or validation, so it
// returns the provided size and never errors.
func (r *ctrRunner) PreRun(_ io.ReaderAt, size int64) (outSize int64, err error) {
	return size, nil
}

// Run implements Runner.
//
// It processes a job concurrently in ranges.
func (r *ctrRunner) Run(ctx context.Context, job *job, opts Options) error {
	blockSize := int64(r.cipher.BlockSize())
	chunks := max((job.size+opts.ChunkSizeBytes-1)/opts.ChunkSizeBytes, 1)
	workers := min(int64(opts.Goroutines), chunks)

	g, ctx := errgroup.WithContext(ctx)
	for i := range workers {
		start := i * chunks / workers
		end := (i + 1) * chunks / workers

		g.Go(func() error {
			buffer := make([]byte, opts.ChunkSizeBytes)

			// copy the initialCounter into each goroutine
			counter := bytes.Clone(r.initialCounter)
			rando.IncrementCounter(counter, uint64(start*opts.ChunkSizeBytes/blockSize))

			crypter := mode.NewCTREncrypter(r.cipher, counter) // same as decrypter
			for j := start; j < end; j++ {
				if err := ctx.Err(); err != nil {
					return err
				}

				offset := j * opts.ChunkSizeBytes
				want := min(opts.ChunkSizeBytes, job.size-offset) // for short tails

				n, err := job.src.ReadAt(buffer[:want], offset)
				if int64(n) != want {
					return fmt.Errorf("short read at %d (%d/%d): %w", offset, n, want, err)
				}

				data := buffer[:want]
				if err := crypter.Crypt(data, data); err != nil {
					return fmt.Errorf("crypt failed at %d: %w", offset, err)
				}

				if _, err = job.dst.WriteAt(data, offset); err != nil {
					return fmt.Errorf("failed to write at %d: %w", offset, err)
				}
			}

			return nil
		})
	}

	return g.Wait()
}
