package core

// MetadataVersion is the current version of Metadata's format.
// It should be bumped when editing Metadata.
const MetadataVersion = 1

// Metadata is a collection of non-sensitive values
// needed to decrypt a file.
type Metadata struct {
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
	Mode          string `json:"mode"`
	PaddingScheme string `json:"padding_scheme,omitempty"`
	IV            string `json:"iv,omitempty"`
	Size          int64  `json:"size"`
	HeaderLength  int64  `json:"header_length"`
	TrailerLength int64  `json:"trailer_length"`
}
