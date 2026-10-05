package orchestration

import (
	"testing"

	"github.com/cryptography-class/aes-des-manipulator/internal/testutil"
)

func TestActionString(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		want   string
	}{
		{
			name:   "encrypt action",
			action: Encrypt,
			want:   "encrypt",
		},
		{
			name:   "decrypt action",
			action: Decrypt,
			want:   "decrypt",
		},
		{
			name:   "unknown action",
			action: -1,
			want:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AssertEqual(t, tt.action.String(), tt.want)
		})
	}
}

func TestModeString(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		want string
	}{
		{
			name: "ECB mode",
			mode: ECB,
			want: "ECB",
		},
		{
			name: "CBC mode",
			mode: CBC,
			want: "CBC",
		},
		{
			name: "CTR mode",
			mode: CTR,
			want: "CTR",
		},
		{
			name: "unknown mode",
			mode: -1,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AssertEqual(t, tt.mode.String(), tt.want)
		})
	}
}
