package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/cryptography-class/aes-des-manipulator/pkg/rando"
	"github.com/spf13/cobra"
)

type KeygenOptions struct {
	// flags
	cipher string

	// positional arguments
	destination string

	// resolved
	dst       AtomicFileWriter
	keyLength int
}

// NewKeygenOptions initializes KeygenOptions.
func NewKeygenOptions() *KeygenOptions {
	return &KeygenOptions{}
}

// AddFlags adds flags to the provided command.
func (k *KeygenOptions) AddFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&k.cipher, flagCipher, "", "block cipher: des|aes-128|aes-192|aes-256")
}

func (k *KeygenOptions) Complete(args []string) error {
	k.destination = strings.TrimSpace(args[0])

	k.cipher = CleanString(k.cipher)

	return nil
}

func (k *KeygenOptions) Validate() error {
	var errs []error
	if _, err := AllowedValue(flagCipher, k.cipher, keys); err != nil {
		errs = append(errs, err)
	}

	if err := FileNotExists(k.destination); err != nil {
		errs = append(errs, ArgumentError(argumentDestination, err))
	}

	return errors.Join(errs...)
}

func (k *KeygenOptions) Resolve() (err error) {
	k.dst, err = NewAtomicFileWriter(k.destination)
	if err != nil {
		return ArgumentError(argumentDestination, err)
	}

	k.keyLength = keys[k.cipher]

	return nil
}

func (k *KeygenOptions) Run(_ context.Context) error {
	defer func() {
		_ = k.dst.Abort()
	}()

	key := rando.RandomBytes(k.keyLength)
	if _, err := k.dst.WriteAt([]byte(hex.EncodeToString(key)), 0); err != nil {
		return fmt.Errorf("[SYSTEM]: the program encountered an unrecoverable error: %w", err)
	}

	if err := k.dst.Commit(); err != nil {
		return fmt.Errorf("the program encountered an error while writing to disk: %w", err)
	}

	return nil
}

// NewKeygenCmd builds a keygen command.
func NewKeygenCmd() *cobra.Command {
	k := NewKeygenOptions()
	cmd := &cobra.Command{
		Use:   "keygen <destination> [options]",
		Short: "Generate a key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ExecuteOptions(k, cmd, args)
		},
	}

	k.AddFlags(cmd)
	return cmd
}
