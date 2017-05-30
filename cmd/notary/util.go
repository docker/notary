package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/notary"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/utils"
	"io/ioutil"
	"os"
)

const (
	// The help text of auto publish
	htAutoPublish string = "Automatically attempt to publish after staging the change. Will also publish existing staged changes."
)

// getPayload is a helper function to get the content used to be verified
// either from an existing file or STDIN.
func getPayload(t *tufCommander) ([]byte, error) {

	// Reads from the given file
	if t.input != "" {
		// Please note that ReadFile will cut off the size if it was over 1e9.
		// Thus, if the size of the file exceeds 1GB, the over part will not be
		// loaded into the buffer.
		payload, err := ioutil.ReadFile(t.input)
		if err != nil {
			return nil, err
		}
		return payload, nil
	}

	// Reads all of the data on STDIN
	payload, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("Error reading content from STDIN: %v", err)
	}
	return payload, nil
}

// feedback is a helper function to print the payload to a file or STDOUT or keep quiet
// due to the value of flag "quiet" and "output".
func feedback(t *tufCommander, payload []byte) error {
	// We only get here when everything goes well, since the flag "quiet" was
	// provided, we output nothing but just return.
	if t.quiet {
		return nil
	}

	// Flag "quiet" was not "true", that's why we get here.
	if t.output != "" {
		return ioutil.WriteFile(t.output, payload, 0644)
	}

	os.Stdout.Write(payload)
	return nil
}

func parseKeysCerts(retriever notary.PassRetriever, privKeys []string, certs []string) (map[string]data.PrivateKey, map[string]data.PublicKey) {
	privateKeys := make(map[string]data.PrivateKey)
	idMap := make(map[string]data.PublicKey)
	for _, fp := range certs {
		byt, err := ioutil.ReadFile(fp)
		if err != nil {
			logrus.Errorf("could not read file at %s", fp)
			continue
		}
		pubKey, err := utils.ParsePEMPublicKey(byt)
		if err != nil {
			logrus.Errorf("could not parse key found in file %s, received error: %s", fp, err.Error())
			continue
		}
		canonicalID, err := utils.CanonicalKeyID(pubKey)
		if err != nil {
			logrus.Errorf("could not generate canonical ID for key found in file %s, received error: %s", fp, err.Error())
			continue
		}
		idMap[canonicalID] = pubKey
	}

	for _, fp := range privKeys {
		byt, err := ioutil.ReadFile(fp)
		if err != nil {
			logrus.Errorf("could not read file at %s", fp)
			continue
		}
		privKey, _, err := trustmanager.GetPasswdDecryptBytes(retriever, byt, "", fp)
		if err != nil {
			logrus.Errorf("could not parse key found in file %s, received error: %s", fp, err.Error())
			continue
		}
		if pubKey, ok := idMap[privKey.ID()]; ok {
			// if we have a matching public key, use the non-canonical ID
			privateKeys[pubKey.ID()] = privKey
			// we found the key, remove it from the map
			delete(idMap, pubKey.ID())
		} else {
			privateKeys[privKey.ID()] = privKey
		}
	}

	return privateKeys, idMap
}
