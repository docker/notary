package store

import (
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
)

// MetadataStore must be implemented by anything that intends to interact
// with a store of TUF files
type MetadataStore interface {
	GetMeta(name string, size int64) ([]byte, error)
	SetMeta(name string, blob []byte) error
	SetMultiMeta(map[string][]byte) error
	RemoveAll() error
	RemoveMeta(name string) error
}

// PublicKeyStore must be implemented by a key service
type PublicKeyStore interface {
	GetKey(role string) (data.PublicKey, error)
	RotateKey(role string, cs signed.CryptoService, roots ...data.PublicKey) (data.PublicKey, error)
}

// LocalStore represents a local TUF sture
type LocalStore interface {
	MetadataStore
}

// RemoteStore is similar to LocalStore with the added expectation that it should
// provide a way to download targets once located
type RemoteStore interface {
	MetadataStore
	PublicKeyStore
}
