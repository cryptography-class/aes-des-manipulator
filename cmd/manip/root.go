/*
Copyright © 2026 ItakawaM maksymworkp@gmail.com
*/
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:          "manip",
	Short:        "Cryptography CLI for modern ciphers.",
	SilenceUsage: true,
}

// Execute runs the root command with context.
func Execute() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := rootCmd.ExecuteContext(ctx)
	cancel()

	if err != nil {
		os.Exit(1)
	}
}

// init registers all commands in rootCmd.
func init() {
	rootCmd.AddCommand(
		NewEncryptCmd(),
	)
}
