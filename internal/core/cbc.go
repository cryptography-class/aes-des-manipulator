package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/mode"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
	"golang.org/x/sync/errgroup"
)

// cbcRunner implements runner for CBC.
type cbcRunner struct {
	cipher    block.Cipher
	action    Action
	padder    *padding.Padder
	initialIv []byte
}

// newCBCRunner initializes a new cbcRunner with the provided cipher, iv and padder.
// It errors when the length of the iv does not match cipher's blocksize.
// It panics on an unknown action.
func newCBCRunner(cipher block.Cipher, padder *padding.Padder, iv []byte, action Action) (*cbcRunner, error) {
	switch action {
	case Encrypt, Decrypt:
	default:
		panic("invalid action provided")
	}

	if len(iv) != cipher.BlockSize() {
		return nil, fmt.Errorf("iv length must be %d bytes", cipher.BlockSize())
	}

	return &cbcRunner{
		cipher:    cipher,
		action:    action,
		padder:    padder,
		initialIv: bytes.Clone(iv),
	}, nil
}

// PreRun implements runner.
func (r *cbcRunner) PreRun(src io.ReaderAt, size int64) (outSize int64, err error) {
	blockSize := int64(r.cipher.BlockSize())
	switch r.action {
	case Encrypt:
		tail := make([]byte, size%blockSize)
		padded := r.padder.PadFunc(tail, int(blockSize))

		return size - size%blockSize + int64(len(padded)), nil

	case Decrypt:
		if size == 0 || size%blockSize != 0 {
			return 0, fmt.Errorf("%w: ciphertext length %d is not a positive multiple of block size %d", ErrInvalidData, size, blockSize)
		}

		iv := r.initialIv

		offset := size - blockSize
		if offset != 0 {
			// iv is the previous ciphertext block
			iv = make([]byte, blockSize)
			if n, err := src.ReadAt(iv, offset-blockSize); n != len(iv) {
				return 0, fmt.Errorf("%w: short read at %d (%d/%d): %w", ErrInvalidData, offset-blockSize, n, len(iv), err)
			}
		}

		crypter := mode.NewCBCDecrypter(r.cipher, iv)
		buffer := make([]byte, blockSize)

		if n, err := src.ReadAt(buffer, offset); n != len(buffer) {
			return 0, fmt.Errorf("%w: short read at %d (%d/%d): %w", ErrInvalidData, offset, n, len(buffer), err)
		}

		if err := crypter.Crypt(buffer, buffer); err != nil {
			return 0, fmt.Errorf("%w: crypt failed at %d: %w", ErrInvalidData, offset, err)
		}

		plain, err := r.padder.UnpadFunc(buffer, int(blockSize))
		if err != nil {
			return 0, fmt.Errorf("%w: failed to unpad: %w", ErrInvalidPadding, err)
		}

		return size - (blockSize - int64(len(plain))), nil

	default:
		panic("invalid action provided")
	}
}

// encrypt processes a job using a 3-stage pipeline: reader, crypter and writer.
func (r *cbcRunner) encrypt(ctx context.Context, job *job, opts Options) error {
	blockSize := r.cipher.BlockSize()
	chunks := max((job.size+opts.ChunkSizeBytes-1)/opts.ChunkSizeBytes, 1)
	last := chunks - 1

	pool := sync.Pool{
		New: func() any {
			b := make([]byte, opts.ChunkSizeBytes)
			return &b
		},
	}

	const depth = 4
	input := make(chan *[]byte, depth)
	output := make(chan *[]byte, depth)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { // reader
		defer close(input)
		for index := range chunks {
			chunk := pool.Get().(*[]byte)

			offset := index * opts.ChunkSizeBytes
			want := min(opts.ChunkSizeBytes, job.size-offset) // for short tails
			*chunk = (*chunk)[:want]

			n, err := job.src.ReadAt(*chunk, offset)
			if int64(n) != want {
				return fmt.Errorf("%w: short read at %d (%d/%d): %w", ErrInvalidData, offset, n, want, err)
			}

			select {
			case input <- chunk:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		return nil
	})

	g.Go(func() error { // encrypter
		defer close(output)
		crypter := mode.NewCBCEncrypter(r.cipher, r.initialIv)
		counter := int64(0)
		for chunk := range input {
			if counter == last {
				*chunk = r.padder.PadFunc(*chunk, blockSize)
			}

			if err := crypter.Crypt(*chunk, *chunk); err != nil {
				return fmt.Errorf("%w: crypt failed: %w", ErrInvalidData, err)
			}

			select {
			case output <- chunk:
				counter += 1

			case <-ctx.Done():
				return ctx.Err()
			}
		}

		return nil
	})

	g.Go(func() error { // writer
		counter := int64(0)
		for chunk := range output {
			offset := counter * opts.ChunkSizeBytes
			if _, err := job.dst.WriteAt(*chunk, offset); err != nil {
				return fmt.Errorf("failed to write at %d: %w", offset, err)
			}

			if int64(cap(*chunk)) == opts.ChunkSizeBytes { // skip buffers PadFunc reallocated
				*chunk = (*chunk)[:cap(*chunk)]
				pool.Put(chunk)
			}

			counter += 1
		}

		return nil
	})

	return g.Wait()
}

// decrypt processes a job using an atomic counter and the provided amount of goroutines.
func (r *cbcRunner) decrypt(ctx context.Context, job *job, opts Options) error {
	blockSize := int64(r.cipher.BlockSize())
	chunks := max((job.size+opts.ChunkSizeBytes-1)/opts.ChunkSizeBytes, 1)
	last := chunks - 1

	var counter atomic.Int64

	g, ctx := errgroup.WithContext(ctx)
	for range min(int64(opts.Goroutines), chunks) {
		g.Go(func() error {
			buffer := make([]byte, blockSize+opts.ChunkSizeBytes)
			for {
				if err := ctx.Err(); err != nil {
					return err
				}

				index := counter.Add(1) - 1
				if index >= chunks {
					return nil
				}

				offset := index * opts.ChunkSizeBytes
				want := min(opts.ChunkSizeBytes, job.size-offset)

				iv := buffer[:blockSize]
				data := buffer[blockSize : blockSize+want]

				readBuf, readOff := data, offset
				if index == 0 {
					copy(iv, r.initialIv)
				} else {
					readBuf, readOff = buffer[:blockSize+want], offset-blockSize
				}

				n, err := job.src.ReadAt(readBuf, readOff)
				if n != len(readBuf) {
					return fmt.Errorf("%w: short read at %d (%d/%d): %w", ErrInvalidData, readOff, n, len(readBuf), err)
				}

				if err := mode.NewCBCDecrypter(r.cipher, iv).Crypt(data, data); err != nil {
					return fmt.Errorf("%w: crypt failed: %w", ErrInvalidData, err)
				}

				if index == last {
					// unpad the last chunk/block
					data, err = r.padder.UnpadFunc(data, int(blockSize))
					if err != nil {
						return fmt.Errorf("%w: failed to unpad: %w", ErrInvalidPadding, err)
					}
				}

				if _, err := job.dst.WriteAt(data, offset); err != nil {
					return err
				}
			}
		})
	}

	return g.Wait()
}

// Run implements runner.
func (r *cbcRunner) Run(ctx context.Context, job *job, opts Options) error {
	switch r.action {
	case Encrypt:
		return r.encrypt(ctx, job, opts)

	case Decrypt:
		return r.decrypt(ctx, job, opts)

	default:
		panic("unreachable")
	}
}
