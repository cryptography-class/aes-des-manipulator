package testutil

import "testing"

func TestParseRSP(t *testing.T) {
	output := []Record{
		{
			Name:    "ECBGFSbox128/ENCRYPT/0",
			Section: "ENCRYPT",
			Fields: map[string]string{
				"KEY":        "00000000000000000000000000000000",
				"PLAINTEXT":  "f34481ec3cc627bacd5dc3fb08f273e6",
				"CIPHERTEXT": "0336763e966d92595a567cc9ce537f5e",
			},
		},
		{
			Name:    "ECBGFSbox128/ENCRYPT/1",
			Section: "ENCRYPT",
			Fields: map[string]string{
				"KEY":        "00000000000000000000000000000000",
				"PLAINTEXT":  "9798c4640bad75c7c3227db910174e72",
				"CIPHERTEXT": "a9a1631bf4996954ebc093957b234589",
			},
		},
		{
			Name:    "ECBGFSbox128/DECRYPT/0",
			Section: "DECRYPT",
			Fields: map[string]string{
				"KEY":        "00000000000000000000000000000000",
				"PLAINTEXT":  "f34481ec3cc627bacd5dc3fb08f273e6",
				"CIPHERTEXT": "0336763e966d92595a567cc9ce537f5e",
			},
		},
		{
			Name:    "ECBGFSbox128/DECRYPT/1",
			Section: "DECRYPT",
			Fields: map[string]string{
				"KEY":        "00000000000000000000000000000000",
				"PLAINTEXT":  "9798c4640bad75c7c3227db910174e72",
				"CIPHERTEXT": "a9a1631bf4996954ebc093957b234589",
			},
		},
		{
			Name:    "ECBGFSbox128/DECRYPT/2",
			Section: "DECRYPT",
			Fields: map[string]string{
				"KEY":        "00000000000000000000000000000000",
				"PLAINTEXT":  "96ab5c2ff612d9dfaae8c31f30c42168",
				"CIPHERTEXT": "ff4f8391a6a40ca5b25d23bedd44a597",
			},
		},
	}

	tests := []struct {
		name     string
		filename string
		data     string
		want     []Record
		wantErr  bool
	}{
		{
			name:     "ECBGFSbox128.rsp",
			filename: "ECBGFSbox128",
			data: `
# CAVS 11.1
# Config info for aes_values
# AESVS GFSbox test data for ECB
# State : Encrypt and Decrypt
# Key Length : 128
# Generated on Fri Apr 22 15:11:26 2011

[ENCRYPT]

COUNT = 0
KEY = 00000000000000000000000000000000
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e

COUNT = 1
KEY = 00000000000000000000000000000000
PLAINTEXT = 9798c4640bad75c7c3227db910174e72
CIPHERTEXT = a9a1631bf4996954ebc093957b234589

[DECRYPT]

COUNT = 0
KEY = 00000000000000000000000000000000
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6

COUNT = 1
KEY = 00000000000000000000000000000000
CIPHERTEXT = a9a1631bf4996954ebc093957b234589
PLAINTEXT = 9798c4640bad75c7c3227db910174e72

COUNT = 2
KEY = 00000000000000000000000000000000
CIPHERTEXT = ff4f8391a6a40ca5b25d23bedd44a597
PLAINTEXT = 96ab5c2ff612d9dfaae8c31f30c42168
`,
			want: output,
		},
		{
			name:     "ECBGFSbox128.rsp with many comments",
			filename: "ECBGFSbox128",
			data: `
# CAVS 11.1
# Config info for aes_values
# AESVS GFSbox test data for ECB
# State : Encrypt and Decrypt
# Key Length : 128
# Generated on Fri Apr 22 15:11:26 2011

[ENCRYPT]

COUNT = 0
KEY = 00000000000000000000000000000000
# Some fancy comment here
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e

COUNT = 1
# Some fancy comment here
# Some fancy comment here
KEY = 00000000000000000000000000000000
PLAINTEXT = 9798c4640bad75c7c3227db910174e72
CIPHERTEXT = a9a1631bf4996954ebc093957b234589

[DECRYPT]

# Some fancy comment here
COUNT = 0
KEY = 00000000000000000000000000000000
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6

COUNT = 1
KEY = 00000000000000000000000000000000
CIPHERTEXT = a9a1631bf4996954ebc093957b234589
PLAINTEXT = 9798c4640bad75c7c3227db910174e72

# Some fancy comment here
# Some fancy comment here
			
COUNT = 2
KEY = 00000000000000000000000000000000
CIPHERTEXT = ff4f8391a6a40ca5b25d23bedd44a597
PLAINTEXT = 96ab5c2ff612d9dfaae8c31f30c42168
`,
			want: output,
		},
		{
			name:     "illegal section",
			filename: "ECBGFSbox128",
			data: `
[ENCRYPT]

COUNT = 0
[DECRYPT]
KEY = 00000000000000000000000000000000
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
`,
			wantErr: true,
		},
		{
			name:     "merging records",
			filename: "ECBGFSbox128",
			data: `
[ENCRYPT]

COUNT = 0
KEY = VALUE
COUNT = 0
`,
			wantErr: true,
		},
		{
			name:     "invalid record beginning",
			filename: "ECBGFSbox128",
			data: `
[ENCRYPT]
			
KEY = VALUE
COUNT = 0
`,
			wantErr: true,
		},
		{
			name:     "invalid record row",
			filename: "ECBGFSbox128",
			data: `
[ENCRYPT]

COUNT = 0
KEY  00000000000000000000000000000000
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
`,
			wantErr: true,
		},
		{
			name:     "duplicate key",
			filename: "ECBGFSbox128",
			data: `
[ENCRYPT]

COUNT = 0
KEY = 00000000000000000000000000000000
KEY = 00000000000000000000000000000000
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
`,
			wantErr: true,
		},
		{
			name:     "empty key",
			filename: "ECBGFSbox128",
			data: `
[ENCRYPT]

COUNT = 0
= 00000000000000000000000000000000
PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRSP(tt.filename, tt.data)
			AssertNilError(t, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			AssertDeepEqual(t, got, tt.want)
		})
	}
}
