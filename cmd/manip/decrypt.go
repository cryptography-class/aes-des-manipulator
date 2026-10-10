package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/cryptography-class/aes-des-manipulator/internal/core"
	"github.com/spf13/cobra"
)

// DecryptOptions are options used by the decrypt command.
type DecryptOptions struct {
	CommonOptions

	// flags
	metadataFile string

	iv []byte

	// resolved
	src AtomicFileReader
	dst AtomicFileWriter
	req *core.Request
}

// NewDecryptOptions initializes DecryptOptions.
func NewDecryptOptions() *DecryptOptions {
	return &DecryptOptions{}
}

// AddFlags adds flags to the provided command.
func (d *DecryptOptions) AddFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&d.keyFile, flagKeyFile, "", "path to file containing a hex key")
	f.StringVar(&d.metadataFile, flagMetadataFile, "", "sidecar path (default: <source>"+defaultMetadataPostfix+")")
	f.Int64Var(&d.chunkSize, flagChunkSize, 1<<20, "bytes processed per work unit")
	f.IntVar(&d.goroutines, flagGoroutines, max(1, runtime.NumCPU()/2), "worker count")
}

// Complete implements Options.
func (d *DecryptOptions) Complete(args []string) (err error) {
	d.metadataFile = strings.TrimSpace(d.metadataFile)
	if d.metadataFile == "" {
		d.metadataFile = d.source + defaultMetadataPostfix
	}

	// fast-fail with invalid metadata
	metadata, err := ReadMetadata(d.metadataFile)
	if err != nil {
		return FlagError(flagMetadataFile, err)
	}

	// fast-fail with invalid metadata
	if metadata.Version != core.MetadataVersion {
		return FlagError(flagMetadataFile, fmt.Errorf("invalid metadata version"))
	}

	d.cipher = metadata.Cipher
	d.mode = metadata.Mode
	d.padding = metadata.PaddingScheme
	d.headerLength = metadata.HeaderLength
	d.trailerLength = metadata.TrailerLength

	if err := d.CommonOptions.Complete(args); err != nil {
		return err
	}

	d.iv, err = hex.DecodeString(metadata.IV)
	if err != nil {
		return FlagError(flagMetadataFile, fmt.Errorf("iv is not a valid hex"))
	}

	return nil
}

// Validate implements Options.
func (d *DecryptOptions) Validate() (err error) {
	var errs []error
	if err := d.CommonOptions.Validate(); err != nil {
		errs = append(errs, err)
	}

	if len(d.iv) != 0 && d.mode == ECBMode {
		errs = append(errs, FlagError(flagIVFile, fmt.Errorf("is not used for ECB")))
	}

	return errors.Join(errs...)
}

// Resolve implements Options.
func (d *DecryptOptions) Resolve() (err error) {
	d.key, err = ReadHex(d.keyFile)
	if err != nil {
		return FlagError(flagKeyFile, err)
	}

	cipher, err := ciphers[d.cipher](d.key)
	if err != nil {
		return FlagError(flagKeyFile, err)
	}

	mode := modes[d.mode]
	padder := paddings[d.padding]

	if mode != core.ECB && len(d.iv) != cipher.BlockSize() {
		return FlagError(flagIVFile, fmt.Errorf("invalid IV size: %d, expected: %d", len(d.iv), cipher.BlockSize()))
	}

	if d.src, err = NewAtomicFileReader(d.source); err != nil {
		return ArgumentError(argumentSource, err)
	}

	if d.headerLength > d.src.Size() || d.trailerLength > d.src.Size()-d.headerLength {
		return FlagError(flagHeaderLength+"/"+flagTrailerLength,
			fmt.Errorf("invalid header and/or trailer lengths (%d %d) do not fit in %d file",
				d.headerLength, d.trailerLength, d.src.Size()))
	}

	if d.dst, err = NewAtomicFileWriter(d.destination); err != nil {
		_ = d.src.Close()
		return ArgumentError(argumentDestination, err)
	}

	d.goroutines = min(d.goroutines, runtime.NumCPU())
	d.req = &core.Request{
		Action:        core.Decrypt,
		Mode:          mode,
		Cipher:        cipher,
		Padder:        padder,
		IV:            d.iv,
		Src:           d.src,
		Dst:           d.dst,
		HeaderLength:  d.headerLength,
		TrailerLength: d.trailerLength,
		Options: core.Options{
			ChunkSizeBytes: d.chunkSize,
			Goroutines:     d.goroutines,
		},
	}

	return nil
}

// Run implements Options.
func (d *DecryptOptions) Run(ctx context.Context) error {
	defer func() {
		if err := d.dst.Abort(); err != nil {
			fmt.Println("Destination Cleanup failed:", err)
		}
		_ = d.src.Close()
	}()

	orch := &core.Orchestrator{}
	if err := orch.Process(ctx, d.req); err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidRequest): // not supposed to happen (?)
			return fmt.Errorf("provided flags and arguments are invalid: %w", err)

		case errors.Is(err, core.ErrInvalidData):
			return fmt.Errorf("the program encountered an error while processing a file: %w", err)

		case errors.Is(err, core.ErrInvalidPadding):
			return fmt.Errorf("the program encountered a padding error: %w", err)

		case errors.Is(err, context.Canceled):
			return fmt.Errorf("the program was interrupted: %w", err)

		default:
			return fmt.Errorf("[SYSTEM]: the program encountered an unrecoverable error: %w", err)
		}
	}

	if err := d.dst.Commit(); err != nil {
		// notify the user of the cleanup failure
		return fmt.Errorf("the program encountered an error while writing to disk: %w", err)
	}

	return nil
}

// NewDecryptCmd builds a decrypt command.
func NewDecryptCmd() *cobra.Command {
	d := NewDecryptOptions()
	cmd := &cobra.Command{
		Use:   "decrypt <source> <destination> [options]",
		Short: "Decrypt a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ExecuteOptions(d, cmd, args)
		},
	}

	d.AddFlags(cmd)
	return cmd
}
