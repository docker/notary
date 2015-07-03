package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/docker/notary/trustmanager"
	"github.com/endophage/gotuf/data"
	"github.com/spf13/viper"
)

type cliCryptoService struct {
	privateKeys map[string]*data.PrivateKey
	gun         string
}

func NewCryptoService(gun string) *cliCryptoService {
	return &cliCryptoService{privateKeys: make(map[string]*data.PrivateKey), gun: gun}
}

// Create is used to generate keys for targets, snapshots and timestamps
func (ccs *cliCryptoService) Create(role string) (*data.PublicKey, error) {
	_, cert, err := generateKeyAndCert(ccs.gun)
	if err != nil {
		return nil, err
	}

	// PEM ENcode the certificate, which will be put directly inside of TUF's root.json
	block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemdata := pem.EncodeToMemory(&block)

	// If this key has the role root, save it as a trusted certificate on our certificateStore
	if role == "root" {
		certificateStore.AddCertFromPEM(pemdata)
	}

	return data.NewPublicKey("RSA", string(pemdata)), nil
}

// Sign returns the signatures for data with the given keyIDs
func (ccs *cliCryptoService) Sign(keyIDs []string, payload []byte) ([]data.Signature, error) {
	// Create hasher and hash data
	hash := crypto.SHA256
	hashed := sha256.Sum256(payload)

	signatures := make([]data.Signature, 0, len(keyIDs))
	for _, fingerprint := range keyIDs {
		// Get the PrivateKey filename
		privKeyFilename := filepath.Join(viper.GetString("privDir"), ccs.gun, fingerprint+".key")
		// Read PrivateKey from file
		privPEMBytes, err := ioutil.ReadFile(privKeyFilename)
		if err != nil {
			continue
		}

		// Parse PrivateKey
		privKeyBytes, _ := pem.Decode(privPEMBytes)
		privKey, err := x509.ParsePKCS1PrivateKey(privKeyBytes.Bytes)
		if err != nil {
			return nil, err
		}

		// Sign the data
		sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, hash, hashed[:])
		if err != nil {
			return nil, err
		}

		// Append signatures to result array
		signatures = append(signatures, data.Signature{
			KeyID:     fingerprint,
			Method:    "RSASSA-PKCS1-V1_5-SIGN",
			Signature: sig[:],
		})
	}
	return signatures, nil
}

//TODO (diogo): Add support for EC P384
func generateKeyAndCert(gun string) (crypto.PrivateKey, *x509.Certificate, error) {
	// Generates a new RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate private key: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	// Creates a new Certificate template. We need the certificate to calculate the
	// TUF-compliant keyID
	//TODO (diogo): We're hardcoding the Organization to be the GUN. Probably want to
	// change it
	template := newCertificate(gun, gun)
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the certificate for key: %v", err)
	}

	// Encode the new certificate into PEM
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the certificate for key: %v", err)
	}

	fingerprint := trustmanager.FingerprintCert(cert)
	// The key is going to be stored in the private directory, using the GUN and
	// the filename will be the TUF-compliant ID. The Store takes care of extensions.
	privKeyFilename := filepath.Join(gun, fingerprint)
	privKeyStore.Add(privKeyFilename, trustmanager.KeyToPEM(keyBytes))
	return key, cert, nil
}
