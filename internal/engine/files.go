package engine

import (
	"fmt"
	"os"
)

// Files is a data-struct for Input and Output files.
type Files struct {
	In      *os.File
	Out     *os.File
	size    int64
	outSize int64
}

// Prepare fills size and outSize based on the provided action and blockSize.
// It errors when there are any issues with the Input file,
// its size is not a multiple of blockSize for the Decrypt action
// or the Input and Output files are the same.
func (f *Files) Prepare(action Action, blockSize int64) error {
	inStat, err := f.In.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat input file: %w", err)
	}
	f.size = inStat.Size()

	outStat, err := f.Out.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat output file: %w", err)
	}

	if os.SameFile(inStat, outStat) {
		return fmt.Errorf("input and output file are the same: %s = %s", inStat.Name(), outStat.Name())
	}

	if action == Decrypt && (f.size == 0 || f.size%blockSize != 0) {
		return fmt.Errorf("ciphertext length %d is not a positive multiple of block size", f.size)
	}

	f.outSize = f.size
	if action == Encrypt {
		f.outSize = f.size + blockSize - (f.size % blockSize) // with padding
	}

	return nil
}

// Allocate truncates the Output file to outSize bytes.
func (f *Files) Allocate() error {
	return f.Out.Truncate(f.outSize)
}
