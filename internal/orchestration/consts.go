package orchestration

// Action is a crypt action.
type Action int

const (
	// Encrypt represents an encrypt action.
	Encrypt Action = iota

	// Decrypt represents a decrypt action.
	Decrypt
)

// String implements Stringer.
func (a Action) String() string {
	switch a {
	case Encrypt:
		return "encrypt"

	case Decrypt:
		return "decrypt"

	default:
		return "unknown"
	}
}

// Mode is a crypting mode.
type Mode int

const (
	// ECB represents the Electronic Codebook mode.
	ECB Mode = iota

	// CBC represents the Cipher Block Chaining mode.
	CBC

	// CTR represents the Counter mode.
	CTR
)

// String implements Stringer.
func (m Mode) String() string {
	switch m {
	case ECB:
		return "ECB"

	case CBC:
		return "CBC"

	case CTR:
		return "CTR"

	default:
		return "unknown"
	}
}
