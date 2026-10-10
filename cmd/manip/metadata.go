package main

import (
	"encoding/json"
	"fmt"

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
