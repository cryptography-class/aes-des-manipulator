package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AtomicFileReader is an interface implemented by atomicFile
// for file reading.
// It's supposed to be used as orchestration.Source.
type AtomicFileReader interface {
	io.ReaderAt
	io.Closer

	// Size returns the size of the file in bytes.
	Size() int64
}

// AtomicFileWriter is an interface implemented by atomicFile
// for safe file writing.
// It's supposed to be used as orchestration.Sink.
type AtomicFileWriter interface {
	io.WriterAt

	// Commit syncs the file onto disk and closes it.
	// It should be called after the file is done processing.
	Commit() error

	// Abort closes the file and removes it from disk.
	// It should always be called in a top-level defer function,
	// as it does nothing if Commit succeeds.
	Abort() error

	// Truncate sets the size of the file to the provided.
	// It should be used to avoid constant file resizing.
	Truncate(size int64) error
}

// atomicFile implements AtomicFileReader as orchestration.Source
// and AtomicFileWriter as orchestration.Sink.
type atomicFile struct {
	*os.File
	destination string
	size        int64
	done        bool
}

// NewAtomicFileWriter creates a temporary atomic-* file.
func NewAtomicFileWriter(path string) (AtomicFileWriter, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "atomic-*")
	if err != nil {
		return nil, err
	}

	a := &atomicFile{
		File:        f,
		destination: path,
	}

	return a, nil
}

// NewAtomicFileReader opens the provided file for atomic reading.
// It errors if the provided file is not regular or does not exist.
func NewAtomicFileReader(path string) (AtomicFileReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file %q: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("error stating file %q: %w", path, err)
	}

	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%q is not a regular file", path)
	}

	size := info.Size()
	a := &atomicFile{
		File: f,
		size: size,
	}

	return a, nil
}

// Commit implements AtomicFileWriter.
func (a *atomicFile) Commit() error {
	if a.done {
		return fmt.Errorf("atomic commit: file already processed")
	}

	if err := a.Sync(); err != nil {
		return fmt.Errorf("atomic commit: failed to commit atomic file: %w", err)
	}

	if err := a.Close(); err != nil {
		return fmt.Errorf("atomic commit: failed to close atomic file: %w", err)
	}

	if err := os.Rename(a.Name(), a.destination); err != nil {
		return fmt.Errorf("atomic commit: failed to rename atomic file: %w", err)
	}
	a.done = true

	// we could potentially sync the directory as well, but
	// that's not supported by all systems

	return nil
}

// Abort implements AtomicFileWriter.
func (a *atomicFile) Abort() error {
	if a.done {
		return nil
	}
	a.done = true

	_ = a.Close()
	if err := os.Remove(a.Name()); err != nil {
		return fmt.Errorf("atomic abort: failed to remove atomic files: %w", err)
	}

	return nil
}

// Size implements AtomicFileReader.
func (a *atomicFile) Size() int64 {
	return a.size
}
