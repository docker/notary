package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/keys"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/tuf/utils"
)

// validateUpload checks that the updates being pushed
// are semantically correct and the signatures are correct
// A list of possibly modified updates are returned if all
// validation was successful. This allows the snapshot to be
// created and added if snapshotting has been delegated to the
// server
func validateUpdate(cs signed.CryptoService, gun string, updates []storage.MetaUpdate, store storage.MetaStore) ([]storage.MetaUpdate, error) {
	kdb := keys.NewDB()
	repo := tuf.NewRepo(kdb, cs)
	rootRole := data.RoleName(data.CanonicalRootRole)
	targetsRole := data.RoleName(data.CanonicalTargetsRole)
	snapshotRole := data.RoleName(data.CanonicalSnapshotRole)

	// check that the necessary roles are present:
	roles := make(map[string]storage.MetaUpdate)
	for _, v := range updates {
		roles[v.Role] = v
	}

	var root *data.SignedRoot
	oldRootJSON, err := store.GetCurrent(gun, rootRole)
	if _, ok := err.(*storage.ErrNotFound); err != nil && !ok {
		// problem with storage. No expectation we can
		// write if we can't read so bail.
		logrus.Error("error reading previous root: ", err.Error())
		return nil, err
	}
	if rootUpdate, ok := roles[rootRole]; ok {
		// if root is present, validate its integrity, possibly
		// against a previous root
		if root, err = validateRoot(gun, oldRootJSON, rootUpdate.Data, store); err != nil {
			logrus.Error("ErrBadRoot: ", err.Error())
			return nil, ErrBadRoot{msg: err.Error()}
		}

		// setting root will update keys db
		if err = repo.SetRoot(root); err != nil {
			logrus.Error("ErrValidation: ", err.Error())
			return nil, ErrValidation{msg: err.Error()}
		}
		logrus.Debug("Successfully validated root")
	} else {
		if oldRootJSON == nil {
			return nil, ErrValidation{msg: "no pre-existing root and no root provided in update."}
		}
		parsedOldRoot := &data.SignedRoot{}
		if err := json.Unmarshal(oldRootJSON, parsedOldRoot); err != nil {
			return nil, ErrValidation{msg: "pre-existing root is corrupted and no root provided in update."}
		}
		if err = repo.SetRoot(parsedOldRoot); err != nil {
			logrus.Error("ErrValidation: ", err.Error())
			return nil, ErrValidation{msg: err.Error()}
		}
	}

	// TODO: validate delegated targets roles.
	var t *data.SignedTargets
	if _, ok := roles[targetsRole]; ok {
		if t, err = validateTargets(targetsRole, roles, kdb); err != nil {
			logrus.Error("ErrBadTargets: ", err.Error())
			return nil, ErrBadTargets{msg: err.Error()}
		}
		repo.SetTargets(targetsRole, t)
	}
	logrus.Debug("Successfully validated targets")

	if _, ok := roles[snapshotRole]; ok {
		var oldSnap *data.SignedSnapshot
		oldSnapJSON, err := store.GetCurrent(gun, snapshotRole)
		if _, ok := err.(*storage.ErrNotFound); err != nil && !ok {
			// problem with storage. No expectation we can
			// write if we can't read so bail.
			logrus.Error("error reading previous snapshot: ", err.Error())
			return nil, err
		} else if err == nil {
			oldSnap = &data.SignedSnapshot{}
			if err := json.Unmarshal(oldSnapJSON, oldSnap); err != nil {
				oldSnap = nil
			}
		}

		if err := validateSnapshot(snapshotRole, oldSnap, roles[snapshotRole], roles, kdb); err != nil {
			logrus.Error("ErrBadSnapshot: ", err.Error())
			return nil, ErrBadSnapshot{msg: err.Error()}
		}
		logrus.Debug("Successfully validated snapshot")
	} else {
		// Check:
		//   - we have a snapshot key
		//   - it matches a snapshot key signed into the root.json
		// Then:
		//   - generate a new snapshot
		//   - add it to the updates
		err := prepRepo(gun, repo, store)
		if err != nil {
			return nil, err
		}
		update, err := generateSnapshot(gun, kdb, repo, store)
		if err != nil {
			return nil, err
		}
		updates = append(updates, *update)
	}
	return updates, nil
}

func prepRepo(gun string, repo *tuf.Repo, store storage.MetaStore) error {
	if repo.Root == nil {
		rootJSON, err := store.GetCurrent(gun, data.CanonicalRootRole)
		if err != nil {
			return fmt.Errorf("could not load repo for snapshot generation: %v", err)
		}
		root := &data.SignedRoot{}
		err = json.Unmarshal(rootJSON, root)
		if err != nil {
			return fmt.Errorf("could not load repo for snapshot generation: %v", err)
		}
		repo.SetRoot(root)
	}
	if repo.Targets[data.CanonicalTargetsRole] == nil {
		targetsJSON, err := store.GetCurrent(gun, data.CanonicalTargetsRole)
		if err != nil {
			return fmt.Errorf("could not load repo for snapshot generation: %v", err)
		}
		targets := &data.SignedTargets{}
		err = json.Unmarshal(targetsJSON, targets)
		if err != nil {
			return fmt.Errorf("could not load repo for snapshot generation: %v", err)
		}
		repo.SetTargets(data.CanonicalTargetsRole, targets)
	}
	return nil
}

func generateSnapshot(gun string, kdb *keys.KeyDB, repo *tuf.Repo, store storage.MetaStore) (*storage.MetaUpdate, error) {
	role := kdb.GetRole(data.RoleName(data.CanonicalSnapshotRole))
	if role == nil {
		return nil, ErrBadRoot{msg: "root did not include snapshot role"}
	}

	algo, keyBytes, err := store.GetKey(gun, data.CanonicalSnapshotRole)
	if role == nil {
		return nil, ErrBadRoot{msg: "root did not include snapshot key"}
	}
	foundK := data.NewPublicKey(algo, keyBytes)

	validKey := false
	for _, id := range role.KeyIDs {
		if id == foundK.ID() {
			validKey = true
			break
		}
	}
	if !validKey {
		return nil, ErrBadHierarchy{msg: "no snapshot was included in update and server does not hold current snapshot key for repository"}
	}

	currentJSON, err := store.GetCurrent(gun, data.CanonicalSnapshotRole)
	if err != nil {
		if _, ok := err.(*storage.ErrNotFound); !ok {
			return nil, fmt.Errorf("could not retrieve previous snapshot: %v", err)
		}
	}
	var sn *data.SignedSnapshot
	if currentJSON != nil {
		sn = new(data.SignedSnapshot)
		err := json.Unmarshal(currentJSON, sn)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve previous snapshot: %v", err)
		}
		err = repo.SetSnapshot(sn)
		if err != nil {
			return nil, fmt.Errorf("could not load previous snapshot: %v", err)
		}
	} else {
		err := repo.InitSnapshot()
		if err != nil {
			return nil, fmt.Errorf("could not initialize snapshot: %v", err)
		}
	}
	sgnd, err := repo.SignSnapshot(data.DefaultExpires(data.CanonicalSnapshotRole))
	if err != nil {
		return nil, fmt.Errorf("could not sign snapshot: %v", err)
	}
	sgndJSON, err := json.Marshal(sgnd)
	if err != nil {
		return nil, fmt.Errorf("could not save snapshot: %v", err)
	}
	return &storage.MetaUpdate{
		Role:    data.CanonicalSnapshotRole,
		Version: repo.Snapshot.Signed.Version,
		Data:    sgndJSON,
	}, nil
}

func validateSnapshot(role string, oldSnap *data.SignedSnapshot, snapUpdate storage.MetaUpdate, roles map[string]storage.MetaUpdate, kdb *keys.KeyDB) error {
	s := &data.Signed{}
	err := json.Unmarshal(snapUpdate.Data, s)
	if err != nil {
		return errors.New("could not parse snapshot")
	}
	// version specifically gets validated when writing to store to
	// better handle race conditions there.
	if err := signed.Verify(s, role, 0, kdb); err != nil {
		return err
	}

	snap, err := data.SnapshotFromSigned(s)
	if err != nil {
		return errors.New("could not parse snapshot")
	}
	if !data.ValidTUFType(snap.Signed.Type, data.CanonicalSnapshotRole) {
		return errors.New("snapshot has wrong type")
	}
	err = checkSnapshotEntries(role, oldSnap, snap, roles)
	if err != nil {
		return err
	}
	return nil
}

func checkSnapshotEntries(role string, oldSnap, snap *data.SignedSnapshot, roles map[string]storage.MetaUpdate) error {
	snapshotRole := data.RoleName(data.CanonicalSnapshotRole)
	timestampRole := data.RoleName(data.CanonicalTimestampRole) // just in case
	for r, update := range roles {
		if r == snapshotRole || r == timestampRole {
			continue
		}
		m, ok := snap.Signed.Meta[r]
		if !ok {
			return fmt.Errorf("snapshot missing metadata for %s", r)
		}
		if int64(len(update.Data)) != m.Length {
			return fmt.Errorf("snapshot has incorrect length for %s", r)
		}

		if !checkHashes(m, update.Data) {
			return fmt.Errorf("snapshot has incorrect hashes for %s", r)
		}
	}
	return nil
}

func checkHashes(meta data.FileMeta, update []byte) bool {
	for alg, digest := range meta.Hashes {
		d := utils.DoHash(alg, update)
		if !bytes.Equal(digest, d) {
			return false
		}
	}
	return true
}

func validateTargets(role string, roles map[string]storage.MetaUpdate, kdb *keys.KeyDB) (*data.SignedTargets, error) {
	// TODO: when delegations are being validated, validate parent
	//       role exists for any delegation
	s := &data.Signed{}
	err := json.Unmarshal(roles[role].Data, s)
	if err != nil {
		return nil, fmt.Errorf("could not parse %s", role)
	}
	// version specifically gets validated when writing to store to
	// better handle race conditions there.
	if err := signed.Verify(s, role, 0, kdb); err != nil {
		return nil, err
	}
	t, err := data.TargetsFromSigned(s)
	if err != nil {
		return nil, err
	}
	if !data.ValidTUFType(t.Signed.Type, data.CanonicalTargetsRole) {
		return nil, fmt.Errorf("%s has wrong type", role)
	}
	return t, nil
}

func validateRoot(gun string, oldRoot, newRoot []byte, store storage.MetaStore) (
	*data.SignedRoot, error) {

	var parsedOldRoot *data.SignedRoot
	parsedNewRoot := &data.SignedRoot{}

	if oldRoot != nil {
		parsedOldRoot = &data.SignedRoot{}
		err := json.Unmarshal(oldRoot, parsedOldRoot)
		if err != nil {
			// TODO(david): if we can't read the old root should we continue
			//             here to check new root self referential integrity?
			//             This would permit recovery of a repo with a corrupted
			//             root.
			logrus.Warn("Old root could not be parsed.")
		}
	}
	err := json.Unmarshal(newRoot, parsedNewRoot)
	if err != nil {
		return nil, err
	}

	// Don't update if a timestamp key doesn't exist.
	algo, keyBytes, err := store.GetKey(gun, data.CanonicalTimestampRole)
	if err != nil || algo == "" || keyBytes == nil {
		return nil, fmt.Errorf("no timestamp key for %s", gun)
	}
	timestampKey := data.NewPublicKey(algo, keyBytes)

	if err := checkRoot(parsedOldRoot, parsedNewRoot, timestampKey); err != nil {
		// TODO(david): how strict do we want to be here about old signatures
		//              for rotations? Should the user have to provide a flag
		//              which gets transmitted to force a root update without
		//              correct old key signatures.
		return nil, err
	}

	if !data.ValidTUFType(parsedNewRoot.Signed.Type, data.CanonicalRootRole) {
		return nil, fmt.Errorf("root has wrong type")
	}
	return parsedNewRoot, nil
}

// checkRoot errors if an invalid rotation has taken place, if the
// threshold number of signatures is invalid, if there are an invalid
// number of roles and keys, or if the timestamp keys are invalid
func checkRoot(oldRoot, newRoot *data.SignedRoot, timestampKey data.PublicKey) error {
	rootRole := data.RoleName(data.CanonicalRootRole)
	targetsRole := data.RoleName(data.CanonicalTargetsRole)
	snapshotRole := data.RoleName(data.CanonicalSnapshotRole)
	timestampRole := data.RoleName(data.CanonicalTimestampRole)

	var oldRootRole *data.RootRole
	newRootRole, ok := newRoot.Signed.Roles[rootRole]
	if !ok {
		return errors.New("new root is missing role entry for root role")
	}

	oldThreshold := 1
	rotation := false
	oldKeys := map[string]data.PublicKey{}
	newKeys := map[string]data.PublicKey{}
	if oldRoot != nil {
		// check for matching root key IDs
		oldRootRole = oldRoot.Signed.Roles[rootRole]
		oldThreshold = oldRootRole.Threshold

		for _, kid := range oldRootRole.KeyIDs {
			k, ok := oldRoot.Signed.Keys[kid]
			if !ok {
				// if the key itself wasn't contained in the root
				// we're skipping it because it could never have
				// been used to validate this root.
				continue
			}
			oldKeys[kid] = data.NewPublicKey(k.Algorithm(), k.Public())
		}

		// super simple check for possible rotation
		rotation = len(oldKeys) != len(newRootRole.KeyIDs)
	}
	// if old and new had the same number of keys, iterate
	// to see if there's a difference.
	for _, kid := range newRootRole.KeyIDs {
		k, ok := newRoot.Signed.Keys[kid]
		if !ok {
			// if the key itself wasn't contained in the root
			// we're skipping it because it could never have
			// been used to validate this root.
			continue
		}
		newKeys[kid] = data.NewPublicKey(k.Algorithm(), k.Public())

		if oldRoot != nil {
			if _, ok := oldKeys[kid]; !ok {
				// if there is any difference in keys, a key rotation may have
				// occurred.
				rotation = true
			}
		}
	}
	newSigned, err := newRoot.ToSigned()
	if err != nil {
		return err
	}
	if rotation {
		err = signed.VerifyRoot(newSigned, oldThreshold, oldKeys)
		if err != nil {
			return fmt.Errorf("rotation detected and new root was not signed with at least %d old keys", oldThreshold)
		}
	}
	err = signed.VerifyRoot(newSigned, newRootRole.Threshold, newKeys)
	if err != nil {
		return err
	}
	root, err := data.RootFromSigned(newSigned)
	if err != nil {
		return err
	}

	var timestampKeyIDs []string

	// at a minimum, check the 4 required roles are present
	for _, r := range []string{rootRole, targetsRole, snapshotRole, timestampRole} {
		role, ok := root.Signed.Roles[r]
		if !ok {
			return fmt.Errorf("missing required %s role from root", r)
		}
		// According to the TUF spec, any role may have more than one signing
		// key and require a threshold signature.  However, notary-server
		// creates the timestamp, and there is only ever one, so a threshold
		// greater than one would just always fail validation
		if (r == timestampRole && role.Threshold != 1) || role.Threshold < 1 {
			return fmt.Errorf("%s role has invalid threshold", r)
		}
		if len(role.KeyIDs) < role.Threshold {
			return fmt.Errorf("%s role has insufficient number of keys", r)
		}

		if r == timestampRole {
			timestampKeyIDs = role.KeyIDs
		}
	}

	// ensure that at least one of the timestamp keys specified in the role
	// actually exists

	for _, keyID := range timestampKeyIDs {
		if timestampKey.ID() == keyID {
			return nil
		}
	}
	return fmt.Errorf("none of the following timestamp keys exist: %s",
		strings.Join(timestampKeyIDs, ", "))
}
