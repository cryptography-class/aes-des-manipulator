package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// ReadHex reads the provided file and decodes the hex string.
func ReadHex(path string) ([]byte, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return nil, fmt.Errorf("%s does not exist", path)

		default:
			return nil, err
		}
	}

	b, err := hex.DecodeString(strings.TrimSpace(string(f)))
	if err != nil {
		return nil, fmt.Errorf("invalid hex value")
	}

	return b, nil
}
