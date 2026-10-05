package testutil

import "io"

// TestWriterAt implements io.WriterAt for general testing.
type TestWriterAt struct {
	io.WriterAt
	Data []byte
}

// WriteAt implements io.WriterAt.
func (w *TestWriterAt) WriteAt(p []byte, off int64) (n int, err error) {
	end := int(off) + len(p)

	if end > len(w.Data) {
		newData := make([]byte, end)
		copy(newData, w.Data)
		w.Data = newData
	}

	copy(w.Data[off:], p)
	return len(p), nil
}
