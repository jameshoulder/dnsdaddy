package secrets

import "crypto/sha256"

// sha256Sum is a thin wrapper so keyIdentifier reads as one idea rather than
// two, and so the import of crypto/sha256 sits next to the only thing that
// uses it.
func sha256Sum(b []byte) [sha256.Size]byte { return sha256.Sum256(b) }
