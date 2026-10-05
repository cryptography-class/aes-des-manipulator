package orchestration

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/mode"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
	"golang.org/x/sync/errgroup"
)

// ecbRunner implements Runner for ECB.
type ecbRunner struct {
	crypter mode.Crypter
	action  Action
	padder  *padding.Padder
}

// newECBRunner initializes a new ecbRunner with the provided cipher and padder.
// It does not error.
// It panics on an unknown action.
func newECBRunner(cipher block.Cipher, padder *padding.Padder, action Action) (*ecbRunner, error) {
	var ecb mode.Crypter
	switch action {
	case Encrypt:
		ecb = mode.NewECBEncrypter(cipher)

	case Decrypt:
		ecb = mode.NewECBDecrypter(cipher)

	default:
		panic("invalid action provided")
	}

	return &ecbRunner{
		crypter: ecb,
		action:  action,
		padder:  padder,
	}, nil
}

// PreRun implements Runner.
func (r *ecbRunner) PreRun(src io.ReaderAt, size int64) (outSize int64, err error) {
	blockSize := int64(r.crypter.BlockSize())
	switch r.action {
	case Encrypt:
		tail := make([]byte, size%blockSize)
		padded := r.padder.PadFunc(tail, int(blockSize))

		return size - size%blockSize + int64(len(padded)), nil

	case Decrypt:
		if size == 0 || size%blockSize != 0 {
			return 0, fmt.Errorf("ciphertext length %d is not a positive multiple of block size %d", size, blockSize)
		}

		offset := size - blockSize
		buffer := make([]byte, blockSize)
		if n, err := src.ReadAt(buffer, offset); n != len(buffer) {
			return 0, fmt.Errorf("short read at %d (%d/%d): %w", offset, n, len(buffer), err)
		}

		if err := r.crypter.Crypt(buffer, buffer); err != nil {
			return 0, fmt.Errorf("crypt failed at %d: %w", offset, err)
		}

		plain, err := r.padder.UnpadFunc(buffer, int(blockSize))
		if err != nil {
			return 0, fmt.Errorf("failed to unpad: %w", err)
		}

		return size - (blockSize - int64(len(plain))), nil

	default:
		panic("unreachable")
	}
}

// Run implements Runner.
//
// It processes a job using an atomic counter and the provided amount of goroutines.
func (r *ecbRunner) Run(ctx context.Context, job *job, opts Options) error {
	blockSize := r.crypter.BlockSize()
	chunks := max((job.size+opts.ChunkSizeBytes-1)/opts.ChunkSizeBytes, 1)
	last := chunks - 1

	var counter atomic.Int64

	g, ctx := errgroup.WithContext(ctx)
	for range min(int64(opts.Goroutines), chunks) {
		g.Go(func() error {
			buffer := make([]byte, opts.ChunkSizeBytes)
			for {
				if err := ctx.Err(); err != nil {
					return err
				}

				index := counter.Add(1) - 1
				if index >= chunks {
					return nil
				}

				offset := index * opts.ChunkSizeBytes
				want := min(opts.ChunkSizeBytes, job.size-offset) // for short tails

				n, err := job.src.ReadAt(buffer[:want], offset)
				if int64(n) != want {
					return fmt.Errorf("short read at %d (%d/%d): %w", offset, n, want, err)
				}

				data := buffer[:want]
				if index == last && r.action == Encrypt {
					// pad the last chunk/block
					data = r.padder.PadFunc(data, blockSize)
				}

				if err := r.crypter.Crypt(data, data); err != nil {
					return fmt.Errorf("crypt failed at %d: %w", offset, err)
				}

				if index == last && r.action == Decrypt {
					// unpad the last chunk/block
					data, err = r.padder.UnpadFunc(data, blockSize)
					if err != nil {
						return fmt.Errorf("failed to unpad: %w", err)
					}
				}

				if _, err = job.dst.WriteAt(data, offset); err != nil {
					return fmt.Errorf("failed to write at %d: %w", offset, err)
				}
			}
		})
	}

	return g.Wait()
}
