package client

import (
	"encoding/json"
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/docker/notary"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"io"
	"io/ioutil"
)

// AddTargetToFile adds the target to the file found at filePath, and writes the updated and re-signed version
// to the outBuf.
// If signingKeys are provided, they are used to sign the file. If lookupKeys are provided, they
// will be looked up in the CryptoService and used for signing where found.
// If _both_ signingKeys, and lookupKeys are provided, the public keys in lookupKeys will be added to signingKeys
// and the merged list will be used for signing.
// If _neither_ signingKeys, no lookupKeys are provided, the key IDs associated with any existing signatures are
// used to search for keys in the CryptoService and used to sign.
func AddTargetToFile(baseDir string, retriever notary.PassRetriever, outBuf io.Writer, filePath string, target *Target, signingKeys map[string]data.PrivateKey, lookupKeys map[string]data.PublicKey) error {
	// do some setup
	var fakeRole data.RoleName = data.CanonicalTargetsRole
	ks, err := getKeyStores(baseDir, retriever)
	if err != nil {
		return err
	}
	cs := cryptoservice.NewCryptoService(ks...)

	var parsed *data.SignedTargets
	if filePath == "-" {
		// setting the filePath to "-" indicates we have no starting file, a new one should be created
		parsed = data.NewTargets()
	} else {
		// read and parse input file
		file, err := ioutil.ReadFile(filePath)
		if err != nil {
			return err
		}

		parsed = &data.SignedTargets{}
		err = json.Unmarshal(file, parsed)
		if err != nil {
			return err
		}
	}

	// add target
	parsed.Signed.Targets[target.Name] = data.FileMeta{
		Length: target.Length,
		Hashes: target.Hashes,
	}

	// sign file
	parsed.Signed.Expires = data.DefaultExpires(fakeRole)
	parsed.Signed.Version = parsed.Signed.Version + 1
	signedObj, err := parsed.ToSigned()
	if err != nil {
		return err
	}

	if signingKeys == nil {
		// just in case, we don't want to panic when we try and assign
		signingKeys = make(map[string]data.PrivateKey)
	}
	for canonID, pubKey := range lookupKeys {
		privKey, _, err := cs.GetPrivateKey(canonID)
		if err != nil {
			// log the canonical ID as this would be the filename the person should look for
			logrus.Errorf("key with ID %s not found", canonID)
			continue
		}
		signingKeys[pubKey.ID()] = privKey
	}

	err = signIsolated(cs, signedObj, signingKeys)
	if err != nil {
		return err
	}

	// marshal and output to write buffer
	out, err := json.Marshal(signedObj)
	if err != nil {
		return err
	}
	n, err := outBuf.Write(out)
	if n < len(out) {
		return errors.New("failed to write all output data")
	}
	return err
}

func signIsolated(cs signed.CryptoService, signedObj *data.Signed, signingKeys map[string]data.PrivateKey) error {
	if len(signingKeys) > 0 {
		return signed.SignWithPrivateKeys(
			signedObj,
			signingKeys,
			nil,
		)
	}
	// collect key IDs from current signatures
	keys := make([]data.PublicKey, 0, len(signedObj.Signatures))
	for _, sig := range signedObj.Signatures {
		logrus.Info("no signing keys provided, attempting to look up keys bsaed on existing signature key IDs.")
		key := cs.GetKey(sig.KeyID)
		if key == nil {
			logrus.Infof("unable to find key with ID %s", sig.KeyID)
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return errors.New("unable to find any signing keys")
	}
	return signed.Sign(
		cs,
		signedObj,
		keys,
		1,
		nil,
	)
}
