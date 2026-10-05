package orchestration

import "io"

// Source is the logical input for the Orchestrator.
type Source interface {
	io.ReaderAt

	// Size returns the size of the logical input.
	Size() int64
}

// Sink is the logical output for the Orchestrator.
type Sink interface {
	io.WriterAt

	// Truncate adjusts the size of the logical output.
	Truncate(size int64) error
}

// copyRegion copies n bytes from dst at dstOffset to src at srcOffset.
func copyRegion(dst io.WriterAt, dstOffset int64, src io.ReaderAt, srcOffset int64, n int64) error {
	if n == 0 {
		return nil
	}

	_, err := io.Copy(io.NewOffsetWriter(dst, dstOffset), io.NewSectionReader(src, srcOffset, n))
	return err
}
