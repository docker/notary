package passphrase

// PassphraseStore is the interface to store/retrieve passphrase from any specific implementation type.
type PassphraseStore interface {
  // Get passphrase from storage.
	GetPassphrase(alias string) (string, error)

  // Set passphrase in storage.
	SetPassphrase(alias string, newPassphrase string) error
}

// PassphraseProtector is the interface to wrap/unwrap passphrase using any specific implementation type.
type PassphraseProtector interface {
  // Wrap the passphrase passed in as clear text.
	Encrypt(clearText string) (string, error)

  // Unwrap the passphrase passed in as cipher text.
	Decrypt(cipherText string) (string, error)
}
