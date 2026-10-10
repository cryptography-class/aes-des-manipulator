package main

import (
	stdaes "crypto/aes"
	stddes "crypto/des"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/cryptography-class/aes-des-manipulator/internal/core"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
)

// constants for allowed values.
const (
	DESCipher    = "des"
	STDDesCipher = "std-des"
	AES128Cipher = "aes-128"
	AES192Cipher = "aes-192"
	AES256Cipher = "aes-256"
	STDAesCipher = "std-aes"

	ECBMode = "ecb"
	CBCMode = "cbc"
	CTRMode = "ctr"

	PKCS7Padding    = "pkcs7"
	ANSIX923Padding = "ansix923"
	NonePadding     = "none"
)

// CleanString trims and lowers a provided string.
func CleanString(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// FlagError wraps a flag error.
func FlagError(name string, err error) error {
	return fmt.Errorf("--%s: %w", name, err)
}

// ArgumentError wraps an argument error.
func ArgumentError(name string, err error) error {
	return fmt.Errorf("%s: %w", name, err)
}

// AllowedValue checks whether the provided flag value is allowed.
// It returns a formatted FlagError when the value is not allowed.
func AllowedValue[T any](flag string, value string, allowed map[string]T) (bool, error) {
	if value == "" {
		return false, FlagError(flag, fmt.Errorf("required"))
	}

	_, ok := allowed[value]
	if !ok {
		return false, FlagError(flag, fmt.Errorf("unsupported %q (supported: %s)",
			value, strings.Join(slices.Sorted(maps.Keys(allowed)), ", ")))
	}

	return true, nil
}

// FileExists checks whether the provided file exists.
// It errors when the file does not exist or stat fails.
func FileExists(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return fmt.Errorf("%s does not exist", path)

		default:
			return err
		}
	}

	return nil
}

// FileNotExists checks whether the provided file does not exist.
// It errors when the file exists.
func FileNotExists(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("%s already exists", path)
	}

	return nil
}

var (
	// ciphers are all the allowed ciphers.
	ciphers = map[string]func(key []byte) (block.Cipher, error){
		DESCipher: des.NewDES,
		STDDesCipher: func(key []byte) (block.Cipher, error) {
			return stddes.NewCipher(key)
		},
		STDAesCipher: func(key []byte) (block.Cipher, error) {
			return stdaes.NewCipher(key)
		},
	}

	// modes are all the allowed modes.
	modes = map[string]core.Mode{
		ECBMode: core.ECB,
		CBCMode: core.CBC,
		CTRMode: core.CTR,
	}

	// paddings are all the allowed padding schemes.
	paddings = map[string]*padding.Padder{
		PKCS7Padding:    padding.NewPKCS7(),
		ANSIX923Padding: padding.NewANSIX923(),
		NonePadding:     nil,
	}

	// keys are all the allowed keys schemas.
	keys = map[string]int{
		DESCipher:    des.KeyLength,
		AES128Cipher: 16,
		AES192Cipher: 24,
		AES256Cipher: 32,
	}
)
