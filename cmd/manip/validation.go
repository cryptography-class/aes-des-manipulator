package main

import (
	stdaes "crypto/aes"
	stddes "crypto/des"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/cryptography-class/aes-des-manipulator/internal/core"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
)

// constants for allowed values.
const (
	DESCipher       = "des"
	STDDesCipher    = "std-des"
	STDAES128Cipher = "std-aes-128"
	STDAES192Cipher = "std-aes-192"
	STDAES256Cipher = "std-aes-256"

	AES128KeyLength = 16
	AES192KeyLength = 24
	AES256KeyLength = 32

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
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("%s already exists", path)
	}

	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	return fmt.Errorf("checking %s: %w", path, err)
}

// ResolvePath returns an absolute, cleaned path in which symlinks are resolved
// for the longest existing prefix.
func ResolvePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	cur := filepath.Clean(abs)
	var rest []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(append([]string{resolved}, rest...)...), nil
		}

		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("resolving %s: %w", cur, err)
		}

		parent := filepath.Dir(cur)
		if parent == cur { // reached the root without finding anything
			return "", fmt.Errorf("resolving %s: %w", path, err)
		}

		rest = append([]string{filepath.Base(cur)}, rest...)
		cur = parent
	}
}

// SameFile checks whether pathA and pathB lead to the same file.
func SameFile(pathA, pathB string) (bool, error) {
	fa, err := os.Stat(pathA)
	if err != nil {
		return false, err
	}

	fb, err := os.Stat(pathB)
	if err != nil {
		return false, err
	}

	return os.SameFile(fa, fb), nil
}

// SamePath checks whether pathA and pathB are the same.
// It differs from SameFile as it does not catch symlinks.
func SamePath(pathA, pathB string) (bool, error) {
	absA, err := ResolvePath(pathA)
	if err != nil {
		return false, err
	}

	absB, err := ResolvePath(pathB)
	if err != nil {
		return false, err
	}

	if runtime.GOOS == "windows" {
		return strings.EqualFold(absA, absB), nil
	}

	return absA == absB, nil
}

var (
	// ciphers are all the allowed ciphers.
	ciphers = map[string]func(key []byte) (block.Cipher, error){
		DESCipher: des.NewDES,
		STDDesCipher: func(key []byte) (block.Cipher, error) {
			return stddes.NewCipher(key)
		},
		STDAES128Cipher: func(key []byte) (block.Cipher, error) {
			if len(key) != AES128KeyLength {
				return nil, fmt.Errorf("invalid key length: %d, expected: %d", len(key), AES128KeyLength)
			}

			return stdaes.NewCipher(key)
		},
		STDAES192Cipher: func(key []byte) (block.Cipher, error) {
			if len(key) != AES192KeyLength {
				return nil, fmt.Errorf("invalid key length: %d, expected: %d", len(key), AES192KeyLength)
			}

			return stdaes.NewCipher(key)
		},
		STDAES256Cipher: func(key []byte) (block.Cipher, error) {
			if len(key) != AES256KeyLength {
				return nil, fmt.Errorf("invalid key length: %d, expected: %d", len(key), AES256KeyLength)
			}

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
		DESCipher:       des.KeyLength,
		STDDesCipher:    des.KeyLength,
		STDAES128Cipher: AES128KeyLength,
		STDAES192Cipher: AES192KeyLength,
		STDAES256Cipher: AES256KeyLength,
	}
)
