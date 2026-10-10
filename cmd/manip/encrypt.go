package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cryptography-class/aes-des-manipulator/internal/core"
	"github.com/cryptography-class/aes-des-manipulator/pkg/rando"
	"github.com/spf13/cobra"
)

// EncryptOptions are options used by the encrypt command
type EncryptOptions struct {
	CommonOptions

	// flags
	ivFile       string
	metadataFile string

	// resolved
	iv  []byte
	src AtomicFileReader
	dst AtomicFileWriter
	req *core.Request
}

// NewEncryptOptions initializes EncryptOptions.
func NewEncryptOptions() *EncryptOptions {
	return &EncryptOptions{}
}

// constants for argument and flag values.
const (
	flagIVFile       = "iv-file"
	flagMetadataFile = "metadata-file"
)

// AddFlags adds flags to the provided command.
func (e *EncryptOptions) AddFlags(cmd *cobra.Command) {
	e.CommonOptions.AddFlags(cmd)

	f := cmd.Flags()
	f.StringVar(&e.ivFile, flagIVFile, "", "file with hex IV/nonce; random one is generated when omitted (cbc/ctr) (random generation is recommended)")
	f.StringVar(&e.metadataFile, flagMetadataFile, "", "sidecar path (default: <destination>"+defaultMetadataPostfix+")")
}

// Complete implements Options.
func (e *EncryptOptions) Complete(args []string) error {
	if err := e.CommonOptions.Complete(args); err != nil {
		return err
	}

	e.ivFile = strings.TrimSpace(e.ivFile)
	e.metadataFile = strings.TrimSpace(e.metadataFile)
	if e.metadataFile == "" {
		e.metadataFile = e.destination + defaultMetadataPostfix
	}

	return nil
}

// Validate implements Options.
func (e *EncryptOptions) Validate() error {
	var errs []error
	if err := e.CommonOptions.Validate(); err != nil {
		errs = append(errs, err)
	}

	if e.ivFile != "" && e.mode == ECBMode {
		errs = append(errs, FlagError(flagIVFile, fmt.Errorf("is not used for ECB")))
	}

	// reject metadata files that point to destination
	// as they would overwrite the file
	if e.metadataFile == e.destination {
		errs = append(errs, FlagError(flagMetadataFile, fmt.Errorf("must differ from destination")))
	}

	if err := FileNotExists(e.metadataFile); err != nil {
		errs = append(errs, FlagError(flagMetadataFile, err))
	}

	return errors.Join(errs...)
}

// Resolve implements Options.
func (e *EncryptOptions) Resolve() (err error) {
	e.key, err = ReadHex(e.keyFile)
	if err != nil {
		return FlagError(flagKeyFile, err)
	}

	cipher, err := ciphers[e.cipher](e.key)
	if err != nil {
		return FlagError(flagKeyFile, err)
	}

	mode := modes[e.mode]
	padder := paddings[e.padding]

	if e.ivFile != "" {
		e.iv, err = ReadHex(e.ivFile)
		if err != nil {
			return FlagError(flagIVFile, err)
		}
	} else if mode != core.ECB { // generate a random valid IV
		e.iv = rando.RandomBytes(cipher.BlockSize())
	}

	if mode != core.ECB && len(e.iv) != cipher.BlockSize() {
		return FlagError(flagIVFile, fmt.Errorf("invalid IV size: %d, expected: %d", len(e.iv), cipher.BlockSize()))
	}

	if e.src, err = NewAtomicFileReader(e.source); err != nil {
		return ArgumentError(argumentSource, err)
	}

	if e.headerLength > e.src.Size() || e.trailerLength > e.src.Size()-e.headerLength {
		return FlagError(flagHeaderLength+"/"+flagTrailerLength,
			fmt.Errorf("invalid header and/or trailer lengths (%d %d) do not fit in %d file",
				e.headerLength, e.trailerLength, e.src.Size()))
	}

	if e.dst, err = NewAtomicFileWriter(e.destination); err != nil {
		_ = e.src.Close()
		return ArgumentError(argumentDestination, err)
	}

	e.goroutines = min(e.goroutines, runtime.NumCPU())
	e.req = &core.Request{
		Action:        core.Encrypt,
		Mode:          mode,
		Cipher:        cipher,
		Padder:        padder,
		IV:            e.iv,
		Src:           e.src,
		Dst:           e.dst,
		HeaderLength:  e.headerLength,
		TrailerLength: e.trailerLength,
		Options: core.Options{
			ChunkSizeBytes: e.chunkSize,
			Goroutines:     e.goroutines,
		},
	}

	return nil
}

// Run implements Options.
func (e *EncryptOptions) Run(ctx context.Context) error {
	defer func() {
		_ = e.dst.Abort()
		_ = e.src.Close()
	}()

	orch := &core.Orchestrator{}
	if err := orch.Process(ctx, e.req); err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidRequest): // not supposed to happen (?)
			return fmt.Errorf("provided flags and arguments are invalid: %w", err)

		case errors.Is(err, core.ErrInvalidData):
			return fmt.Errorf("the program encountered an error while processing a file: %w", err)

		case errors.Is(err, core.ErrInvalidPadding):
			return fmt.Errorf("the program encountered a padding error")

		case errors.Is(err, context.Canceled):
			return fmt.Errorf("the program was interrupted")

		default:
			return fmt.Errorf("[SYSTEM]: the program encountered an unrecoverable error: %w", err)
		}
	}

	if err := WriteMetadata(e.metadataFile, core.Metadata{
		Cipher:        e.cipher,
		Mode:          e.mode,
		PaddingScheme: e.padding,
		IV:            hex.EncodeToString(e.iv),
		Size:          e.src.Size(),
		HeaderLength:  e.headerLength,
		TrailerLength: e.trailerLength,
	}); err != nil {
		return fmt.Errorf("the program encountered an error while writing metadata: %w", err)
	}

	if err := e.dst.Commit(); err != nil {
		// notify the user of the cleanup failure
		if cleanupErr := os.Remove(e.metadataFile); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf(
				"the program encountered an error while writing to disk: %w",
				errors.Join(err, fmt.Errorf("metadata cleanup failed: %w", cleanupErr)),
			)
		}

		return fmt.Errorf("the program encountered an error while writing to disk: %w", err)
	}

	return nil
}

// NewEncryptCmd builds an encrypt command.
func NewEncryptCmd() *cobra.Command {
	e := NewEncryptOptions()
	cmd := &cobra.Command{
		Use:   "encrypt <source> <destination> [options]",
		Short: "Encrypt a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ExecuteOptions(e, cmd, args)
		},
	}

	e.AddFlags(cmd)
	return cmd
}
