package core

// MetadataVersion is the current version of MetadataSidecart's format.
// It should be bumped when editing MetadataSidecart.
const MetadataVersion = 1

// MetadataSidecart is a collection of non-sensitive values
// needed to decrypt a file.
type MetadataSidecart struct {
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
	Mode          string `json:"mode"`
	PaddingScheme string `json:"padding_scheme,omitempty"`
	IV            string `json:"iv,omitempty"`
	Size          int64  `json:"size"`
	HeaderLength  int64  `json:"header_length"`
	TrailerLength int64  `json:"trailer_length"`
}
