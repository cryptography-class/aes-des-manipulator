package engine

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/mode"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
	"golang.org/x/sync/errgroup"
)

// ProcessECB concurrently processes a file using ECB mode with the provided cipher and padder.
func (e *Engine) ProcessECB(f Files, cipher block.Cipher, action Action, padder padding.Padder) error {
	blockSize := int64(cipher.BlockSize())
	if e.chunkSizeBytes%blockSize != 0 {
		return fmt.Errorf("engine: chunk size %d is not a multiple of block size %d", e.chunkSizeBytes, blockSize)
	}

	if err := f.Prepare(action, blockSize); err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	chunks := max((f.size+e.chunkSizeBytes-1)/e.chunkSizeBytes, 1)
	last := chunks - 1

	var ecb mode.Crypter
	switch action {
	case Encrypt:
		ecb = mode.NewECBEncrypter(cipher)
	case Decrypt:
		ecb = mode.NewECBDecrypter(cipher)
	}

	// check the padding before processing
	if action == Decrypt {
		offset := f.size - blockSize

		buffer := make([]byte, blockSize)
		n, err := f.In.ReadAt(buffer, offset)
		if err != nil || n != int(blockSize) {
			return fmt.Errorf("engine: short read at %d (%d/%d): %w", offset, n, blockSize, err)
		}

		if err := ecb.Crypt(buffer, buffer); err != nil {
			return fmt.Errorf("engine: crypt failed at %d: %w", offset, err)
		}

		plain, err := padder.UnpadFunc(buffer, int(blockSize))
		if err != nil {
			return fmt.Errorf("engine: failed to unpad: %w", err)
		}
		f.outSize = f.size - (blockSize - int64(len(plain)))
	}

	if err := f.Allocate(); err != nil {
		return fmt.Errorf("engine: error allocating output file: %w", err)
	}

	// counter is the index of the next chunk
	var counter atomic.Int64

	// group with context, so we can stop processing on an error
	g, ctx := errgroup.WithContext(context.Background())
	for range e.goroutines {
		g.Go(func() error {
			// a reusable buffer per worker
			buffer := make([]byte, e.chunkSizeBytes)
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				index := counter.Add(1) - 1
				if index >= chunks {
					return nil
				}

				offset := index * e.chunkSizeBytes
				want := min(e.chunkSizeBytes, f.size-offset) // for short tails

				n, err := f.In.ReadAt(buffer[:want], offset)
				if int64(n) != want || err != nil {
					return fmt.Errorf("short read at %d (%d/%d): %w", offset, n, want, err)
				}

				data := buffer[:want]
				if index == last && action == Encrypt {
					// pad the last chunk/block
					data = padder.PadFunc(data, int(blockSize))
				}

				if err := ecb.Crypt(data, data); err != nil {
					return fmt.Errorf("crypt failed at %d: %w", offset, err)
				}

				if index == last && action == Decrypt {
					// unpad the last chunk/block
					data, err = padder.UnpadFunc(data, int(blockSize))
					if err != nil {
						return fmt.Errorf("failed to unpad: %w", err)
					}
				}

				if _, err = f.Out.WriteAt(data, offset); err != nil {
					return fmt.Errorf("failed to write at %d: %w", offset, err)
				}
			}
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("engine: processing failed: %w", err)
	}

	return nil
}
