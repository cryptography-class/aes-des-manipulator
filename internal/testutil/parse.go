// Package testutil implements generic utils for testing and unit test parsing.
package testutil

import (
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sectionRe matches [SECTION].
var sectionRe = regexp.MustCompile(`^\[([^]]+)]$`)

// ParseFunc parses record into T.
//
// It errors on missing/invalid required fields.
type ParseFunc[T any] func(r Record) (T, error)

// Record is a single parsed .rsp record.
type Record struct {
	Name    string
	Section string
	Fields  map[string]string
}

// Hex decodes a hex-string field by its key.
//
// It errors when the value is not a valid hex,
// or the length of a parsed slice does not equal wantLength.
func (r *Record) Hex(key string, wantLength int) ([]byte, error) {
	raw, ok := r.Fields[key]
	if !ok {
		return nil, fmt.Errorf("field %s not found", key)
	}

	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %s is not a valid hex string: %v", key, raw, err)
	}

	if len(b) != wantLength {
		return nil, fmt.Errorf("%s=%s got length = %d, want = %d", key, raw, len(b), wantLength)
	}

	return b, nil
}

// TestFolder is a wrapper around an embedded testdata folder
// with a glob match pattern for file reading.
type TestFolder struct {
	FS    *embed.FS
	Match string
}

// ParseTests reads all of the files inside folder and parses them into
// structs via the provided parse function.
//
// It errors when no matching files were found, file format is invalid
// or parsing failed.
func ParseTests[T any](t *testing.T, folder *TestFolder, parse ParseFunc[T]) []T {
	t.Helper()

	files, err := fs.Glob(folder.FS, folder.Match)
	if err != nil {
		t.Fatalf("%s: failed to read testdata: %s", folder.Match, err)
	}

	if len(files) == 0 {
		t.Fatalf("%s: no test files found", folder.Match)
	}

	var out []T
	for _, filename := range files {
		read, err := folder.FS.ReadFile(filename)
		if err != nil {
			t.Fatalf("%s: failed to read testdata: %s", filename, err)
		}
		data := string(read)
		base := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))

		records, err := parseRSP(base, data)
		if err != nil {
			t.Fatalf("%s: failed to parse test data: %s", filename, err)
		}

		// fail hard on empty test files
		if len(records) == 0 {
			t.Fatalf("%s: empty test file", filename)
		}

		for _, record := range records {
			parsed, err := parse(record)
			if err != nil {
				t.Fatalf("%s: failed to parse record: %s", record.Name, err)
			}
			out = append(out, parsed)
		}
	}

	return out
}

const countKey = "COUNT"

// parseRSP parses NIST .rsp file format.
//
// Convention:
//  1. # denotes a comment. They are skipped.
//  2. [SECTION] is a beginning of a section. Sections can't exist inside records.
//  3. COUNT = some_number is a beginning of a key = value record.
//
// It errors when an illegal section is present inside a record,
// a key = value pair is broken or a duplicate key was found.
func parseRSP(filename string, data string) ([]Record, error) {
	var out []Record

	var current *Record
	section := "UNKNOWN" // placeholder
	for raw := range strings.SplitSeq(data, "\n") {
		raw = strings.TrimSpace(raw)
		if current == nil {
			if raw == "" {
				continue
			}

			// skip comments
			if strings.HasPrefix(raw, "#") {
				continue
			}

			// beginning of a section
			matches := sectionRe.FindStringSubmatch(raw)
			if len(matches) == 2 {
				section = matches[1]
				continue
			}

			// a record MUST start with "COUNT = some_number"
			key, value, ok := strings.Cut(raw, "=")
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if !ok || key != countKey {
				return nil, fmt.Errorf("invalid record row beginning: %s", raw)
			}

			current = &Record{
				Name:    fmt.Sprintf("%s/%s/%s", filename, section, value),
				Section: section,
				Fields:  make(map[string]string),
			}
		} else {
			// an empty line ends the Record
			if raw == "" {
				out = append(out, *current)
				current = nil
				continue
			}

			// skip comments
			if strings.HasPrefix(raw, "#") {
				continue
			}

			// illegal section
			if sectionRe.MatchString(raw) {
				return nil, fmt.Errorf("[section] is not allowed inside a record: %s", raw)
			}

			key, value, ok := strings.Cut(raw, "=")
			if !ok {
				// invalid record row
				return nil, fmt.Errorf("invalid record row: %s", raw)
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)

			switch key {
			case countKey:
				return nil, fmt.Errorf("two merging records with no newline: %s", raw)

			case "":
				return nil, fmt.Errorf("empty key: %s", raw)
			}

			if _, ok := current.Fields[key]; ok {
				return nil, fmt.Errorf("duplicate record key: %s", raw)
			}

			current.Fields[key] = value
		}
	}

	// flush at the end
	if current != nil {
		out = append(out, *current)
	}

	return out, nil
}
