package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cryptography-class/aes-des-manipulator/internal/core"
)

// defaultMetadataPostfix is the default file extension used for metadata files.
const defaultMetadataPostfix = ".metadata"

// WriteMetadata writes metadata to the provided file.
func WriteMetadata(path string, out core.Metadata) error {
	out.Version = core.MetadataVersion

	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return fmt.Errorf("format error: %w", err)
	}
	data = append(data, '\n')

	w, err := NewAtomicFileWriter(path)
	if err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	defer func() {
		_ = w.Abort()
	}()

	if _, err := w.WriteAt(data, 0); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	if err := w.Commit(); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}

// ReadMetadata reads metadata from the provided file.
func ReadMetadata(path string) (core.Metadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return core.Metadata{}, fmt.Errorf("%s does not exist", path)

		default:
			return core.Metadata{}, fmt.Errorf("read metadata: %w", err)
		}
	}

	var out core.Metadata
	if err := json.Unmarshal(data, &out); err != nil {
		return core.Metadata{}, fmt.Errorf("invalid metadata format")
	}

	return out, nil
}
