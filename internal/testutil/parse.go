package testutil

import (
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestCaseParser is the interface implemented by unit test structs.
type TestCaseParser[T any] interface {
	// Parse parses fields into a struct of type T and sets the name of the test to name.
	// It errors when the provided fields do not meet the structure of a unit test.
	Parse(name string, fields []string) (T, error)
}

// TestFolder is a wrapper around an embedded testdata folder
// with a glob match pattern for file reading.
type TestFolder struct {
	FS    *embed.FS
	Match string
}

// ParseTests loads unit tests of type T from every file in folder.FS matching folder.Match.
// Each file holds comma-separated test rows.
// Fields from a whitespace-separated row are passed to T's Parse method to build the case.
// Any read, glob or parse failure fails the test.
func ParseTests[T TestCaseParser[T]](t *testing.T, folder *TestFolder) []T {
	t.Helper()

	files, err := fs.Glob(folder.FS, folder.Match)
	if err != nil {
		t.Fatalf("failed to read testdata: %s", err)
	}

	if len(files) == 0 {
		t.Fatalf("no test files found for %s", folder.Match)
	}

	var out []T
	for _, filename := range files {
		read, err := folder.FS.ReadFile(filename)
		if err != nil {
			t.Fatalf("%s: failed to read testdata: %s", filename, err)
		}
		data := string(read)

		base := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
		counter := 1
		for line := range strings.SplitSeq(data, ",") {
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			fields := strings.Fields(line)
			name := fmt.Sprintf("%s_%d", base, counter)

			var zero T
			parsed, err := zero.Parse(name, fields)
			if err != nil {
				t.Fatalf("%s: failed to parse testdata %q: %s", name, fields, err)
			}

			counter++
			out = append(out, parsed)
		}
	}

	return out
}

// ParseHex parses raw into a slice of bytes.
// It errors when raw is not a valid hex, or the length of a parsed slice does not equal wantLen.
func ParseHex(name string, raw string, wantLen int) ([]byte, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to decode hex %s: %s", name, raw, err)
	}

	if len(b) != wantLen {
		return nil, fmt.Errorf("%s: expected %d bytes, got %d: %q", name, wantLen, len(b), raw)
	}

	return b, nil
}
