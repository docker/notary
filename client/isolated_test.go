package client

import (
	"bytes"
	"crypto/rand"
	"github.com/docker/notary"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	tufutils "github.com/docker/notary/tuf/utils"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"testing"
)

func TestSignIsolated(t *testing.T) {
	privKey, err := tufutils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	tgt := data.NewTargets()
	sgnd, err := tgt.ToSigned()
	require.NoError(t, err)

	require.NoError(t, signIsolated(
		nil, // we don't use the cryptoservice when specific private keys are provided
		sgnd,
		map[string]data.PrivateKey{
			privKey.ID(): privKey,
		},
	))

	cs := cryptoservice.NewCryptoService(
		trustmanager.NewKeyMemoryStore(passphraseRetriever),
	)

	// no signing keys provided and no keys in cryptoservice
	require.Error(t, signIsolated(
		cs, // we don't use the cryptoservice when specific private keys are provided
		sgnd,
		nil,
	))

	// add the key
	require.NoError(t, cs.AddKey("targets", "", privKey))

	// allow key to be detected via signature key ID
	require.NoError(t, signIsolated(
		cs, // we don't use the cryptoservice when specific private keys are provided
		sgnd,
		nil,
	))
}

func TestAddTargetToFile(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	require.NoError(t, err)

	privKey, err := tufutils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	out := new(bytes.Buffer)

	require.NoError(t, AddTargetToFile(
		tmpDir,
		passphraseRetriever,
		out,
		"-", // create a new file
		&Target{
			Name: "isolated",
			Hashes: data.Hashes{
				notary.SHA256: []byte("abcdef"),
			},
			Length: 0xdeadbeef,
		},
		map[string]data.PrivateKey{
			privKey.ID(): privKey,
		},
		nil,
	))

	tmpFile, err := ioutil.TempFile("", "notary-test-targets-")
	require.NoError(t, err)

	io.Copy(tmpFile, out)
	tmpFile.Close()

	filePath := tmpFile.Name()

	// check we error when no keys are provided and no keys are in the key storage
	require.Error(t, AddTargetToFile(
		tmpDir,
		passphraseRetriever,
		out,
		filePath,
		&Target{
			Name: "isolated",
			Hashes: data.Hashes{
				notary.SHA256: []byte("abcdef"),
			},
			Length: 0xdeadbeef,
		},
		nil,
		nil,
	))

	// reset out buffer
	out = new(bytes.Buffer)

	require.NoError(t, AddTargetToFile(
		tmpDir,
		passphraseRetriever,
		out,
		filePath,
		&Target{
			Name: "isolated",
			Hashes: data.Hashes{
				notary.SHA256: []byte("abcdef"),
			},
			Length: 0xdeadbeef,
		},
		map[string]data.PrivateKey{
			privKey.ID(): privKey,
		},
		nil,
	))

	// Add private key to key stores and check we can sign when
	// looking up the signature ID
	ks, err := getKeyStores(tmpDir, passphraseRetriever)
	require.NoError(t, err)
	cs := cryptoservice.NewCryptoService(ks...)
	err = cs.AddKey("targets", "", privKey)
	require.NoError(t, err)

	// reset out buffer
	out = new(bytes.Buffer)

	require.NoError(t, AddTargetToFile(
		tmpDir,
		passphraseRetriever,
		out,
		filePath, // create a new file
		&Target{
			Name: "isolated",
			Hashes: data.Hashes{
				notary.SHA256: []byte("abcdef"),
			},
			Length: 0xdeadbeef,
		},
		nil,
		nil,
	))

	// reset out buffer
	out = new(bytes.Buffer)

	// check that we can sign when we provide lookup keys that are in the key store.
	require.NoError(t, AddTargetToFile(
		tmpDir,
		passphraseRetriever,
		out,
		"-", // create a new file to guarantee we're not looking up signature key IDs
		&Target{
			Name: "isolated",
			Hashes: data.Hashes{
				notary.SHA256: []byte("abcdef"),
			},
			Length: 0xdeadbeef,
		},
		nil,
		map[string]data.PublicKey{
			privKey.ID(): data.PublicKeyFromPrivate(privKey),
		},
	))
}
