package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/cryptography-class/aes-des-manipulator/internal/core/bench"
	"github.com/spf13/cobra"
)

// Options is a pipeline implemented by core commands.
// It validates and resolves input values, before running the actual
// flow of the command.
// Its methods should be run one after another in the given order:
//
// Complete -> Validate -> Resolve -> Run
type Options interface {
	// Complete fills in values from positional arguments,
	// lowercases and trims inputs.
	Complete(args []string) error

	// Validate checks if the provided positional and
	// flag values are valid for a given command.
	// It returns a joined error that consists of all invalid values.
	Validate() error

	// Resolve maps the provided values to
	// their logical types.
	Resolve() error

	// Run executes the command flow.
	Run(ctx context.Context) error
}

// ExecuteOptions executes the given options.
// It's the body of all commands' RunE.
func ExecuteOptions(opts Options, cmd *cobra.Command, args []string) error {
	if verbose, _ := cmd.Flags().GetBool(flagVerbose); verbose {
		defer bench.MeasurePerformance()()
	}

	if err := opts.Complete(args); err != nil {
		return err
	}

	if err := opts.Validate(); err != nil {
		return err
	}

	if err := opts.Resolve(); err != nil {
		return err
	}

	return opts.Run(cmd.Context())
}

// CommonOptions are options shared by encrypt and decrypt commands.
type CommonOptions struct {
	// flags
	cipher        string
	mode          string
	padding       string
	keyFile       string
	chunkSize     int64
	goroutines    int
	headerLength  int64
	trailerLength int64

	// positional arguments
	source      string
	destination string

	// resolved
	key []byte
}

// constants for argument and flag values.
const (
	argumentSource      = "source"
	argumentDestination = "destination"

	flagCipher        = "cipher"
	flagMode          = "mode"
	flagPadding       = "padding"
	flagKeyFile       = "key-file"
	flagChunkSize     = "chunk-size"
	flagGoroutines    = "goroutines"
	flagHeaderLength  = "header-length"
	flagTrailerLength = "trailer-length"
)

// AddFlags adds shared flags to the provided command.
func (c *CommonOptions) AddFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&c.cipher, flagCipher, "", "block cipher: des|std-des|std-aes")
	f.StringVar(&c.mode, flagMode, "", "mode of operation: ecb|cbc|ctr")
	f.StringVar(&c.padding, flagPadding, "", "padding scheme: pkcs7|ansix923|none")
	f.StringVar(&c.keyFile, flagKeyFile, "", "path to file containing a hex key")
	f.Int64Var(&c.chunkSize, flagChunkSize, 1<<20, "bytes processed per work unit")
	f.IntVar(&c.goroutines, flagGoroutines, max(1, runtime.NumCPU()/2), "worker count")
	f.Int64Var(&c.headerLength, flagHeaderLength, 0, "bytes at the start copied verbatim")
	f.Int64Var(&c.trailerLength, flagTrailerLength, 0, "bytes at the end copied verbatim")
}

// Complete fills in positional arguments and cleans arguments and flags.
func (c *CommonOptions) Complete(args []string) error {
	c.source = strings.TrimSpace(args[0])
	c.destination = strings.TrimSpace(args[1])

	c.cipher = CleanString(c.cipher)
	c.mode = CleanString(c.mode)
	c.padding = CleanString(c.padding)
	c.keyFile = strings.TrimSpace(c.keyFile)

	return nil
}

// Validate checks positional arguments and flags for invalid values.
// It returns a joined error.
func (c *CommonOptions) Validate() error {
	var errs []error

	_, err := AllowedValue(flagCipher, c.cipher, ciphers)
	if err != nil {
		errs = append(errs, err)
	}

	allowedMode, err := AllowedValue(flagMode, c.mode, modes)
	if err != nil {
		errs = append(errs, err)
	}

	var allowedPadding bool
	if c.mode != CTRMode {
		allowedPadding, err = AllowedValue(flagPadding, c.padding, paddings)
		if err != nil {
			errs = append(errs, err)
		}
	} else {
		// default CTR to none padding
		c.padding = NonePadding
	}

	if allowedMode && allowedPadding && c.mode != CTRMode && c.padding == NonePadding {
		errs = append(errs, FlagError(flagMode, fmt.Errorf("%s requires padding", c.mode)))
	}

	if c.chunkSize <= 0 {
		errs = append(errs, FlagError(flagChunkSize, fmt.Errorf("must be > 0")))
	}

	if c.goroutines <= 0 {
		errs = append(errs, FlagError(flagGoroutines, fmt.Errorf("must be > 0")))
	}

	if c.headerLength < 0 {
		errs = append(errs, FlagError(flagHeaderLength, fmt.Errorf("must be >= 0")))
	}

	if c.trailerLength < 0 {
		errs = append(errs, FlagError(flagTrailerLength, fmt.Errorf("must be >= 0")))
	}

	if err := FileExists(c.source); err != nil {
		errs = append(errs, ArgumentError(argumentSource, err))
	}

	if err := FileExists(c.keyFile); err != nil {
		errs = append(errs, FlagError(flagKeyFile, err))
	}

	if err := FileNotExists(c.destination); err != nil {
		errs = append(errs, ArgumentError(argumentDestination, err))
	}

	return errors.Join(errs...)
}
