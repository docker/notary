package cryptoservice

import (
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/docker/notary/trustmanager"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCertificate(t *testing.T) {
	privKey, err := trustmanager.GenerateECDSAKey(rand.Reader)
	assert.NoError(t, err, "could not generate key")

	keyStore := trustmanager.NewKeyMemoryStore(passphraseRetriever)

	err = keyStore.AddKey(privKey.ID(), "root", privKey)
	assert.NoError(t, err, "could not add key to store")

	// Check GenerateCertificate method
	gun := "docker.com/notary"
	cert, err := GenerateCertificate(privKey, gun)
	assert.NoError(t, err, "could not generate certificate")

	// Check public key
	ecdsaPrivateKey, err := x509.ParseECPrivateKey(privKey.Private())
	assert.NoError(t, err)
	ecdsaPublicKey := ecdsaPrivateKey.Public()
	assert.Equal(t, ecdsaPublicKey, cert.PublicKey)

	// Check CommonName
	assert.Equal(t, cert.Subject.CommonName, gun)
}
