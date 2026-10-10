package core

import (
	"bytes"
	"fmt"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

// testSource implements Source for testing.
type testSource struct {
	*bytes.Reader
}

func newTestSource(b []byte) *testSource {
	return &testSource{
		bytes.NewReader(b),
	}
}

// testSink implements Sink for testing.
type testSink struct {
	*testutil.TestWriterAt
}

func newTestSink() *testSink {
	return &testSink{
		&testutil.TestWriterAt{},
	}
}

// Truncate implements Sink.
func (t *testSink) Truncate(size int64) error {
	if size <= 0 {
		return fmt.Errorf("invalid size provided: %d", size)
	}

	buffer := make([]byte, size)
	copy(buffer, t.Data)
	t.Data = buffer

	return nil
}
