package core

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
	"github.com/cryptography-class/aes-des-manipulator/pkg/block/des"
	"github.com/cryptography-class/aes-des-manipulator/pkg/padding"
)

func TestRequestValidate(t *testing.T) {
	cipher, err := des.NewDES([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("NewDes() error: %v", err)
	}

	validRequest := Request{
		Action:        Encrypt,
		Mode:          CBC,
		Cipher:        cipher,
		Padder:        padding.NewPKCS7(),
		IV:            []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Src:           newTestSource([]byte{1, 2, 3, 4}),
		Dst:           newTestSink(),
		HeaderLength:  1,
		TrailerLength: 1,
		Options: Options{
			ChunkSizeBytes: 8,
			Goroutines:     2,
		},
	}

	tests := []struct {
		name      string
		req       Request
		wantPanic bool
		err       error
	}{
		{
			name: "valid",
			req:  validRequest,
		},
		// Panics
		{
			name: "nil cipher, src, dst",
			req: Request{
				Cipher: nil,
				Src:    nil,
				Dst:    nil,
			},
			wantPanic: true,
		},
		{
			name: "unknown action",
			req: Request{
				Action: -1,
				Cipher: cipher,
				Src:    newTestSource([]byte{1, 23}),
				Dst:    newTestSink(),
			},
			wantPanic: true,
		},
		{
			name: "unknown mode",
			req: Request{
				Action: Encrypt,
				Mode:   -1,
				Cipher: cipher,
				Src:    newTestSource([]byte{1, 23}),
				Dst:    newTestSink(),
			},
			wantPanic: true,
		},
		{
			name: "ECB without padding",
			req: Request{
				Action: Encrypt,
				Mode:   ECB,
				Cipher: cipher,
				Padder: nil,
				Src:    newTestSource([]byte{1, 23}),
				Dst:    newTestSink(),
			},
			wantPanic: true,
		},
		{
			name: "CTR with padding",
			req: Request{
				Action: Encrypt,
				Mode:   CTR,
				Cipher: cipher,
				Padder: padding.NewPKCS7(),
				Src:    newTestSource([]byte{1, 23}),
				Dst:    newTestSink(),
			},
			wantPanic: true,
		},
		// Errors
		{
			name: "invalid header length",
			req: func(r Request) Request {
				r.HeaderLength = -1
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
		{
			name: "invalid trailer length",
			req: func(r Request) Request {
				r.TrailerLength = -1
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
		{
			name: "invalid header and trailer length",
			req: func(r Request) Request {
				r.HeaderLength = 2
				r.TrailerLength = 3
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
		{
			name: "invalid IV",
			req: func(r Request) Request {
				r.IV = []byte{1, 2, 3, 4, 5, 6, 7}
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
		{
			name: "nil IV",
			req: func(r Request) Request {
				r.IV = nil
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
		{
			name: "invalid chunk size bytes 1",
			req: func(r Request) Request {
				r.ChunkSizeBytes = -1
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
		{
			name: "invalid chunk size bytes 2",
			req: func(r Request) Request {
				r.ChunkSizeBytes = 9 // not mod blocksize
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
		{
			name: "invalid goroutines",
			req: func(r Request) Request {
				r.Goroutines = -1
				return r
			}(validRequest),
			err: ErrInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				testutil.AssertPanic(t, recover(), tt.wantPanic)
			}()

			err := tt.req.validate()
			testutil.AssertError(t, err, tt.err)
			if tt.err != nil {
				return
			}
		})
	}
}
