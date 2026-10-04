package orchestration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/mode"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
	"golang.org/x/sync/errgroup"
)

// cbcRunner implements Runner for CBC.
type cbcRunner struct {
	cipher    block.Cipher
	action    Action
	padder    *padding.Padder
	initialIv []byte
}

// newCBCRunner initializes a new cbcRunner with the provided cipher, iv and padder.
// It errors when the length of the iv does not match cipher's blocksize.
func newCBCRunner(cipher block.Cipher, padder *padding.Padder, iv []byte, action Action) (*cbcRunner, error) {
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

func (r *cbcRunner) PreRun(src io.ReaderAt, size int64) (outSize int64, err error) {
	blockSize := int64(r.cipher.BlockSize())
	switch r.action {
	case Encrypt:
		tail := make([]byte, size%blockSize)
		padded := r.padder.PadFunc(tail, int(blockSize))

		return size - size%blockSize + int64(len(padded)), nil

	case Decrypt:
		if size == 0 || size%blockSize != 0 {
			return 0, fmt.Errorf("ciphertext length %d is not a positive multiple of block size %d", size, blockSize)
		}

		iv := r.initialIv

		offset := size - blockSize
		if offset != 0 {
			// iv is the previous ciphertext block
			iv = make([]byte, blockSize)
			if n, err := src.ReadAt(iv, offset-blockSize); n != len(iv) {
				return 0, fmt.Errorf("short read at %d (%d/%d): %w", offset-blockSize, n, len(iv), err)
			}
		}

		crypter := mode.NewCBCDecrypter(r.cipher, iv)
		buffer := make([]byte, blockSize)

		if n, err := src.ReadAt(buffer, offset); n != len(buffer) {
			return 0, fmt.Errorf("short read at %d (%d/%d): %w", offset, n, len(buffer), err)
		}

		if err := crypter.Crypt(buffer, buffer); err != nil {
			return 0, fmt.Errorf("crypt failed at %d: %w", offset, err)
		}

		plain, err := r.padder.UnpadFunc(buffer, int(blockSize))
		if err != nil {
			return 0, fmt.Errorf("failed to unpad: %w", err)
		}

		return size - (blockSize - int64(len(plain))), nil

	default:
		panic("invalid action provided")
	}
}

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
				return fmt.Errorf("short read at %d (%d/%d): %w", offset, n, want, err)
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
				return fmt.Errorf("crypt failed: %w", err)
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

func (r *cbcRunner) decrypt(ctx context.Context, job *job, opts Options) error {
	panic("NOT IMPLEMENTED")
}

func (r *cbcRunner) Run(ctx context.Context, job *job, opts Options) error {
	switch r.action {
	case Encrypt:
		return r.encrypt(ctx, job, opts)

	case Decrypt:
		return r.decrypt(ctx, job, opts)

	default:
		panic("invalid action provided")
	}
}
