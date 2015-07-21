// Package passphrase is a utility function for managing passphrase
// for TUF and Notary keys.
package passphrase

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/pkg/term"
)

// Retriever is a callback function that should retrieve a passphrase
// for a given named key. If it should be treated as new passphrase (e.g. with
// confirmation), createNew will be true. Attempts is passed in so that implementers
// decide how many chances to give to a human, for example.
type Retriever func(keyName, alias string, createNew bool, attempts int) (passphrase string, giveup bool, err error)

const (
	tufRootAlias = "root"
	tufTargetsAlias = "targets"
	tufSnapshotAlias = "snapshot"
)

// PromptRetriever returns a new Retriever which will provide a terminal prompt
// to retrieve a passphrase. The passphrase will be cached such that subsequent
// prompts will produce the same passphrase.
func PromptRetriever() Retriever {
	userEnteredTargetsSnapshotsPass := false
	targetsSnapshotsPass := ""
	userEnteredRootsPass := false
	rootsPass := ""

	return func(keyName string, alias string, createNew bool, numAttempts int) (string, bool, error) {
		// First, check if we have a password cached for this alias.
		if numAttempts == 0 {
			if userEnteredTargetsSnapshotsPass && (alias == tufSnapshotAlias || alias == tufTargetsAlias) {
				return targetsSnapshotsPass, false, nil
			}
			if userEnteredRootsPass && (alias == "root") {
				return rootsPass, false, nil
			}
		}

		if numAttempts > 3 && !createNew {
			return "", true, errors.New("Too many attempts")
		}

		state, err := term.SaveState(0)
		if err != nil {
			return "", false, err
		}
		term.DisableEcho(0, state)
		defer term.RestoreTerminal(0, state)

		stdin := bufio.NewReader(os.Stdin)

		if createNew {
			fmt.Printf("Enter passphrase for new %s key with id %s: ", alias, keyName)
		} else {
			fmt.Printf("Enter key passphrase for %s key with id %s: ", alias, keyName)
		}

		passphrase, err := stdin.ReadBytes('\n')
		fmt.Println()
		if err != nil {
			return "", false, err
		}

		retPass := strings.TrimSpace(string(passphrase))

		if !createNew {
			if alias == tufSnapshotAlias || alias == tufTargetsAlias {
				userEnteredTargetsSnapshotsPass = true
				targetsSnapshotsPass = retPass
			}
			if alias == tufRootAlias {
				userEnteredRootsPass = true
				rootsPass = retPass
			}
			return retPass, false, nil
		}

		if len(retPass) < 8 {
			fmt.Println("Please use a password manager to generate and store a good random passphrase.")
			return "", false, errors.New("Passphrase too short")
		}

		fmt.Printf("Repeat passphrase for new %s key with id %s: ", alias, keyName)
		confirmation, err := stdin.ReadBytes('\n')
		fmt.Println()
		if err != nil {
			return "", false, err
		}
		confirmationStr := strings.TrimSpace(string(confirmation))

		if retPass != confirmationStr {
			return "", false, errors.New("The entered passphrases do not match")
		}

		if alias == tufSnapshotAlias || alias == tufTargetsAlias {
			userEnteredTargetsSnapshotsPass = true
			targetsSnapshotsPass = retPass
		}
		if alias == tufRootAlias {
			userEnteredRootsPass = true
			rootsPass = retPass
		}

		return retPass, false, nil
	}
}
