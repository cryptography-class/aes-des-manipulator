package gcm

import (
	"embed"
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

//go:embed testdata/ghash/*.rsp
var ghashTestDataFS embed.FS

const (
	ghashMatch = "testdata/ghash/*.rsp"
)

// ghashTestCase is a single test case for GHASH.
type ghashTestCase struct {
	name       string
	h          []byte
	aad        []byte
	ciphertext []byte
	hash       []byte
}

func parseGHASHKAT(r testutil.Record) (ghashTestCase, error) {
	var zero ghashTestCase
	h, err := r.Hex("H", 16)
	if err != nil {
		return zero, err
	}

	aad, err := r.Hex("AAD")
	if err != nil {
		return zero, err
	}

	ciphertext, err := r.Hex("CIPHERTEXT")
	if err != nil {
		return zero, err
	}

	hash, err := r.Hex("GHASH", 16)
	if err != nil {
		return zero, err
	}

	return ghashTestCase{
		name:       r.Name,
		h:          h,
		aad:        aad,
		ciphertext: ciphertext,
		hash:       hash,
	}, nil
}

func TestGHASHKAT(t *testing.T) {
	folder := &testutil.TestFolder{
		FS:    &ghashTestDataFS,
		Match: ghashMatch,
	}

	for _, tt := range testutil.ParseTests(t, folder, parseGHASHKAT) {
		t.Run(tt.name, func(t *testing.T) {
			g := newGhash([16]byte(tt.h))
			g.writeAAD(tt.aad)
			g.writeCiphertext(tt.ciphertext)

			testutil.AssertEqual(t, g.sum(), [16]byte(tt.hash))
		})
	}
}

func TestGHASHInvalidWrites(t *testing.T) {
	h := [16]byte{}
	t.Run("writeAAD after writeCiphertext", func(t *testing.T) {
		defer func() {
			testutil.AssertPanic(t, recover(), true)
		}()

		g := newGhash(h)
		g.writeCiphertext([]byte{1, 2, 3})
		g.writeAAD([]byte{1, 2, 3})
	})

	t.Run("writeAAD after sum", func(t *testing.T) {
		defer func() {
			testutil.AssertPanic(t, recover(), true)
		}()

		g := newGhash(h)
		g.writeCiphertext([]byte{1, 2, 3})
		_ = g.sum()
		g.writeAAD([]byte{1, 2, 3})
	})

	t.Run("writeCiphertext after sum", func(t *testing.T) {
		defer func() {
			testutil.AssertPanic(t, recover(), true)
		}()

		g := newGhash(h)
		g.writeCiphertext([]byte{1, 2, 3})
		_ = g.sum()
		g.writeCiphertext([]byte{1, 2, 3})
	})

	t.Run("sum after sum", func(t *testing.T) {
		defer func() {
			testutil.AssertPanic(t, recover(), true)
		}()

		g := newGhash(h)
		g.writeCiphertext([]byte{1, 2, 3})
		_ = g.sum()
		_ = g.sum()
	})
}

func TestGHASHStreaming(t *testing.T) {
	t.Run("streaming", func(t *testing.T) {
		g := newGhash([16]byte{})
		g.writeAAD([]byte{1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3})
		g.writeAAD([]byte{1})

		g.writeCiphertext([]byte{1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3})
		g.writeCiphertext([]byte{1, 2, 3})

		_ = g.sum()
	})
}
