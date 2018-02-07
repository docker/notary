package client

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/theupdateframework/notary"
	store "github.com/theupdateframework/notary/storage"
	"github.com/theupdateframework/notary/trustpinning"
	"github.com/theupdateframework/notary/tuf"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/utils"
)

// Diff represents the difference between two versions of the same repo
type Diff struct {
	TargetsAdded   []TargetSignedStruct
	TargetsRemoved []TargetSignedStruct
	TargetsUpdated []TargetUpdateDiff
	RolesAdded     []data.Role
	RolesRemoved   []data.Role
	RolesUpdated   []RoleUpdateDiff
}

// TargetUpdateDiff records a Target entry that changed by referencing
// the Before and After versions of the TargetSignedStruct
type TargetUpdateDiff struct {
	Before TargetSignedStruct
	After  TargetSignedStruct
}

// RoleUpdateDiff records a Role entry that changed by referencing
// the Before and After versions of the Role
type RoleUpdateDiff struct {
	Before data.Role
	After  data.Role
}

// NewDiff returns the different between two versions of the same TUF repo
func NewDiff(gun data.GUN, baseURL string, rt http.RoundTripper, hash1, hash2 string) (Diff, error) {
	remoteStore, err := getRemoteStore(baseURL, gun, rt)
	if err != nil {
		// baseURL is syntactically invalid
		return Diff{}, err
	}

	first, err := setupClient(gun, hash1, remoteStore)
	if err != nil {
		return Diff{}, err
	}
	second, err := setupClient(gun, hash2, remoteStore)
	if err != nil {
		return Diff{}, err
	}

	// download the relevant versions of the repos now that we have the bootstrapping
	// setup.
	// N.B. lower case update will fail out immediately rather than attempting
	//      to download a newer root
	logrus.Debug("starting updates for repository diff between %s and %s", hash1, hash2)
	err = first.update()
	if err != nil {
		return Diff{}, errors.Wrapf(err, "failed to download repo at version \"%s\"", hash1)
	}
	logrus.Debugf("succeeded updating first repository snapshot at %s", hash1)
	err = second.update()
	if err != nil {
		return Diff{}, errors.Wrapf(err, "failed to download repo at version \"%s\"", hash2)
	}
	logrus.Debug("succeeded updating second repository snapshot at %s", hash2)

	repoFirst, _, err := first.newBuilder.Finish()
	if err != nil {
		return Diff{}, err
	}
	repoSecond, _, err := second.newBuilder.Finish()
	if err != nil {
		return Diff{}, err
	}

	return diff(repoFirst, repoSecond)
}

func setupClient(gun data.GUN, tsHash string, remote store.RemoteStore) (*tufClient, error) {
	hashBytes, err := hex.DecodeString(tsHash)
	if err != nil {
		return nil, errors.Wrapf(err, "could not decode valid hash from hex string \"%s\"", tsHash)
	}

	root, err := findRoot(hashBytes, remote)
	if err != nil {
		return nil, err
	}

	oldBuilder := tuf.NewRepoBuilder(gun, nil, trustpinning.TrustPinConfig{})
	if err := oldBuilder.Load(data.CanonicalRootRole, root, 0, true); err != nil {
		return nil, err
	}
	newBuilder := tuf.NewRepoBuilder(gun, nil, trustpinning.TrustPinConfig{})
	if err := newBuilder.Load(data.CanonicalRootRole, root, 0, true); err != nil {
		return nil, err
	}

	tClient := newTufClient(oldBuilder, newBuilder, remote, store.NewMemoryStore(nil))
	tClient.tsChecksum = hashBytes
	return tClient, nil
}

func diff(first, second *tuf.Repo) (Diff, error) {
	res := Diff{}
	err := diffTargets(&res, first, second)
	if err != nil {
		return res, err
	}
	err = diffRoles(&res, first, second)
	return res, err
}

func diffRoles(res *Diff, first, second *tuf.Repo) error {
	firstRoles := first.GetAllLoadedRoles()
	lookupTable := make(map[string]*data.Role)
	for _, role := range firstRoles {
		lookupTable[role.Name.String()] = role
	}
	secondRoles := second.GetAllLoadedRoles()
	for _, role := range secondRoles {
		found, ok := lookupTable[role.Name.String()]
		if !ok {
			res.RolesAdded = append(res.RolesAdded, *role)
			continue
		}
		delete(lookupTable, role.Name.String())
		if !equivalentRoles(role, found) {
			res.RolesUpdated = append(
				res.RolesUpdated,
				RoleUpdateDiff{
					Before: *found,
					After:  *role,
				},
			)
		}
	}
	for _, role := range lookupTable {
		res.RolesRemoved = append(res.RolesRemoved, *role)
	}
	return nil
}

// equivalentRoles returns that two roles are equivalent if:
// - the paths match
// - the key IDs match
// - the threshold matches
// note: signatures and versions are deliberately not checked
// as equivalent roles can have varying values
func equivalentRoles(first, second *data.Role) bool {
	paths := make(map[string]struct{})
	for _, path := range first.Paths {
		paths[path] = struct{}{}
	}
	for _, path := range second.Paths {
		if _, ok := paths[path]; ok {
			delete(paths, path)
		}
	}
	if len(paths) > 0 {
		return false
	}

	keyIDs := make(map[string]struct{})
	for _, kid := range first.KeyIDs {
		keyIDs[kid] = struct{}{}
	}
	for _, kid := range second.KeyIDs {
		if _, ok := keyIDs[kid]; ok {
			delete(keyIDs, kid)
		}
	}
	if len(keyIDs) > 0 {
		return false
	}

	if first.Threshold != second.Threshold {
		return false
	}
	return true
}

func diffTargets(res *Diff, first, second *tuf.Repo) error {
	logrus.Debugf("getting meta for first")
	firstTgts, err := getAllTargetMetadataByName(*first, "")
	if err != nil {
		if _, ok := err.(ErrNoSuchTarget); !ok {
			return err
		}
	}
	// we'll take firstTgts and create a lookup table of map[role name][target name]TargetSignedStruct
	// then we'll iterate secondTgts and look up each target by role and name to identify if it
	// exists in one but not the other, or has been updated
	lookupTable := make(map[string]map[string]TargetSignedStruct)
	for _, tgt := range firstTgts {
		roleName := tgt.Role.BaseRole.Name.String()
		if lookupTable[roleName] == nil {
			lookupTable[roleName] = make(map[string]TargetSignedStruct)
		}
		lookupTable[roleName][tgt.Target.Name] = tgt
	}

	logrus.Debugf("getting meta for second")
	secondTgts, err := getAllTargetMetadataByName(*second, "")
	if err != nil {
		if _, ok := err.(ErrNoSuchTarget); !ok {
			return err
		}
	}
	for _, tgt := range secondTgts {
		roleName := tgt.Role.BaseRole.Name.String()
		role, ok := lookupTable[roleName]
		if !ok {
			res.TargetsAdded = append(res.TargetsAdded, tgt)
			continue
		}
		found, ok := role[tgt.Target.Name]
		if !ok {
			res.TargetsAdded = append(res.TargetsAdded, tgt)
			continue
		}
		// delete from the lookup table because we found it. Anything left in the
		// lookup table at the end is a removed target
		delete(role, tgt.Target.Name)

		if !equivalentTargets(tgt.Target, found.Target) {
			res.TargetsUpdated = append(
				res.TargetsUpdated,
				TargetUpdateDiff{
					Before: found,
					After:  tgt,
				},
			)
		}
	}

	for _, role := range lookupTable {
		for _, tgt := range role {
			res.TargetsRemoved = append(res.TargetsRemoved, tgt)
		}
	}

	return nil
}

func equivalentTargets(first, second Target) bool {
	return first.Name != second.Name ||
		first.Length != second.Length ||
		!reflect.DeepEqual(first.Hashes, second.Hashes)
}

// walk ts -> snap -> root.
// Verifies content checksums, other verification will be done when we
// eventually call tufClient.update()
func findRoot(tsChecksum []byte, remote store.RemoteStore) ([]byte, error) {
	consistentTSName := utils.ConsistentName(
		data.CanonicalTimestampRole.String(),
		tsChecksum,
	)

	raw, err := remote.GetSized(consistentTSName, notary.MaxTimestampSize)
	if err != nil {
		logrus.Debugf("error downloading %s: %s", consistentTSName, err)
		return nil, err
	}
	if err := data.CheckHashes(raw, data.CanonicalTimestampRole.String(), data.Hashes{notary.SHA256: tsChecksum}); err != nil {
		return nil, err
	}

	ts := &data.SignedTimestamp{}
	err = json.Unmarshal(raw, ts)
	if err != nil {
		logrus.Debugf("error parsing %s: %s", consistentTSName, err)
		return nil, err
	}

	snapshotMeta := ts.Signed.Meta[data.CanonicalSnapshotRole.String()]
	consistentSnapshotName := utils.ConsistentName(
		data.CanonicalSnapshotRole.String(),
		snapshotMeta.Hashes[notary.SHA256],
	)
	raw, err = remote.GetSized(consistentSnapshotName, snapshotMeta.Length)
	if err != nil {
		logrus.Debugf("error downloading %s: %s", consistentSnapshotName, err)
		return nil, err
	}
	if err := data.CheckHashes(raw, data.CanonicalSnapshotRole.String(), snapshotMeta.Hashes); err != nil {
		return nil, err
	}

	snap := &data.SignedSnapshot{}
	err = json.Unmarshal(raw, snap)
	if err != nil {
		logrus.Debugf("error parsing %s: %s", consistentSnapshotName, err)
		return nil, err
	}

	rootMeta := snap.Signed.Meta[data.CanonicalRootRole.String()]
	consistentRootName := utils.ConsistentName(
		data.CanonicalRootRole.String(),
		rootMeta.Hashes["sha256"],
	)
	raw, err = remote.GetSized(consistentRootName, rootMeta.Length)
	if err != nil {
		logrus.Debugf("error downloading %s: %s", consistentRootName, err)
		return nil, err
	}
	if err := data.CheckHashes(raw, data.CanonicalRootRole.String(), rootMeta.Hashes); err != nil {
		return nil, err
	}

	return raw, err
}
