package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/certs"
	"github.com/docker/notary/client/changelist"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf"
	tufclient "github.com/docker/notary/tuf/client"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/keys"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/tuf/store"
)

const (
	maxSize = 5 << 20
)

func init() {
	data.SetDefaultExpiryTimes(
		map[string]int{
			"root":     3650,
			"targets":  1095,
			"snapshot": 1095,
		},
	)
}

// ErrRepoNotInitialized is returned when trying to can publish on an uninitialized
// notary repository
type ErrRepoNotInitialized struct{}

// ErrRepoNotInitialized is returned when trying to can publish on an uninitialized
// notary repository
func (err *ErrRepoNotInitialized) Error() string {
	return "Repository has not been initialized"
}

// ErrExpired is returned when the metadata for a role has expired
type ErrExpired struct {
	signed.ErrExpired
}

const (
	tufDir = "tuf"
)

// ErrRepositoryNotExist gets returned when trying to make an action over a repository
/// that doesn't exist.
var ErrRepositoryNotExist = errors.New("repository does not exist")

// NotaryRepository stores all the information needed to operate on a notary
// repository.
type NotaryRepository struct {
	baseDir       string
	gun           string
	baseURL       string
	tufRepoPath   string
	fileStore     store.MetadataStore
	CryptoService signed.CryptoService
	tufRepo       *tuf.Repo
	roundTrip     http.RoundTripper
	CertManager   *certs.Manager
}

// repositoryFromKeystores is a helper function for NewNotaryRepository that
// takes some basic NotaryRepository parameters as well as keystores (in order
// of usage preference), and returns a NotaryRepository.
func repositoryFromKeystores(baseDir, gun, baseURL string, rt http.RoundTripper,
	keyStores []trustmanager.KeyStore) (*NotaryRepository, error) {

	certManager, err := certs.NewManager(baseDir)
	if err != nil {
		return nil, err
	}

	cryptoService := cryptoservice.NewCryptoService(gun, keyStores...)

	nRepo := &NotaryRepository{
		gun:           gun,
		baseDir:       baseDir,
		baseURL:       baseURL,
		tufRepoPath:   filepath.Join(baseDir, tufDir, filepath.FromSlash(gun)),
		CryptoService: cryptoService,
		roundTrip:     rt,
		CertManager:   certManager,
	}

	fileStore, err := store.NewFilesystemStore(
		nRepo.tufRepoPath,
		"metadata",
		"json",
		"",
	)
	if err != nil {
		return nil, err
	}
	nRepo.fileStore = fileStore

	return nRepo, nil
}

// Target represents a simplified version of the data TUF operates on, so external
// applications don't have to depend on tuf data types.
type Target struct {
	Name   string
	Hashes data.Hashes
	Length int64
}

// NewTarget is a helper method that returns a Target
func NewTarget(targetName string, targetPath string) (*Target, error) {
	b, err := ioutil.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}

	meta, err := data.NewFileMeta(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	return &Target{Name: targetName, Hashes: meta.Hashes, Length: meta.Length}, nil
}

// Initialize creates a new repository by using rootKey as the root Key for the
// TUF repository.
func (r *NotaryRepository) Initialize(rootKeyID string) error {
	privKey, _, err := r.CryptoService.GetPrivateKey(rootKeyID)
	if err != nil {
		return err
	}

	// Hard-coded policy: the generated certificate expires in 10 years.
	startTime := time.Now()
	rootCert, err := cryptoservice.GenerateCertificate(privKey, r.gun, startTime, startTime.Add(time.Hour*24*365*10))

	if err != nil {
		return err
	}
	r.CertManager.AddTrustedCert(rootCert)

	// The root key gets stored in the TUF metadata X509 encoded, linking
	// the tuf root.json to our X509 PKI.
	// If the key is RSA, we store it as type RSAx509, if it is ECDSA we store it
	// as ECDSAx509 to allow the gotuf verifiers to correctly decode the
	// key on verification of signatures.
	var rootKey data.PublicKey
	switch privKey.Algorithm() {
	case data.RSAKey:
		rootKey = data.NewRSAx509PublicKey(trustmanager.CertToPEM(rootCert))
	case data.ECDSAKey:
		rootKey = data.NewECDSAx509PublicKey(trustmanager.CertToPEM(rootCert))
	default:
		return fmt.Errorf("invalid format for root key: %s", privKey.Algorithm())
	}

	// All the timestamp keys are generated by the remote server.
	remote, err := getRemoteStore(r.baseURL, r.gun, r.roundTrip)
	if err != nil {
		return err
	}
	rawTSKey, err := remote.GetKey("timestamp")
	if err != nil {
		return err
	}

	timestampKey, err := data.UnmarshalPublicKey(rawTSKey)
	if err != nil {
		return err
	}

	logrus.Debugf("got remote %s timestamp key with keyID: %s", timestampKey.Algorithm(), timestampKey.ID())

	// This is currently hardcoding the targets and snapshots keys to ECDSA
	// Targets and snapshot keys are always generated locally.
	targetsKey, err := r.CryptoService.Create("targets", data.ECDSAKey)
	if err != nil {
		return err
	}
	snapshotKey, err := r.CryptoService.Create("snapshot", data.ECDSAKey)
	if err != nil {
		return err
	}

	kdb := keys.NewDB()

	kdb.AddKey(rootKey)
	kdb.AddKey(targetsKey)
	kdb.AddKey(snapshotKey)
	kdb.AddKey(timestampKey)

	err = initRoles(kdb, rootKey, targetsKey, snapshotKey, timestampKey)
	if err != nil {
		return err
	}

	r.tufRepo = tuf.NewRepo(kdb, r.CryptoService)

	err = r.tufRepo.InitRoot(false)
	if err != nil {
		logrus.Debug("Error on InitRoot: ", err.Error())
		switch err.(type) {
		case signed.ErrInsufficientSignatures, trustmanager.ErrPasswordInvalid:
		default:
			return err
		}
	}
	err = r.tufRepo.InitTargets()
	if err != nil {
		logrus.Debug("Error on InitTargets: ", err.Error())
		return err
	}
	err = r.tufRepo.InitSnapshot()
	if err != nil {
		logrus.Debug("Error on InitSnapshot: ", err.Error())
		return err
	}

	return r.saveMetadata()
}

// AddTarget adds a new target to the repository, forcing a timestamps check from TUF
func (r *NotaryRepository) AddTarget(target *Target) error {
	cl, err := changelist.NewFileChangelist(filepath.Join(r.tufRepoPath, "changelist"))
	if err != nil {
		return err
	}
	defer cl.Close()
	logrus.Debugf("Adding target \"%s\" with sha256 \"%x\" and size %d bytes.\n", target.Name, target.Hashes["sha256"], target.Length)

	meta := data.FileMeta{Length: target.Length, Hashes: target.Hashes}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	c := changelist.NewTufChange(changelist.ActionCreate, changelist.ScopeTargets, "target", target.Name, metaJSON)
	err = cl.Add(c)
	if err != nil {
		return err
	}
	return nil
}

// RemoveTarget creates a new changelist entry to remove a target from the repository
// when the changelist gets applied at publish time
func (r *NotaryRepository) RemoveTarget(targetName string) error {
	cl, err := changelist.NewFileChangelist(filepath.Join(r.tufRepoPath, "changelist"))
	if err != nil {
		return err
	}
	logrus.Debugf("Removing target \"%s\"", targetName)
	c := changelist.NewTufChange(changelist.ActionDelete, changelist.ScopeTargets, "target", targetName, nil)
	err = cl.Add(c)
	if err != nil {
		return err
	}
	return nil
}

// ListTargets lists all targets for the current repository
func (r *NotaryRepository) ListTargets() ([]*Target, error) {
	c, err := r.bootstrapClient()
	if err != nil {
		return nil, err
	}

	err = c.Update()
	if err != nil {
		if err, ok := err.(signed.ErrExpired); ok {
			return nil, ErrExpired{err}
		}
		return nil, err
	}

	var targetList []*Target
	for name, meta := range r.tufRepo.Targets["targets"].Signed.Targets {
		target := &Target{Name: name, Hashes: meta.Hashes, Length: meta.Length}
		targetList = append(targetList, target)
	}

	return targetList, nil
}

// GetTargetByName returns a target given a name
func (r *NotaryRepository) GetTargetByName(name string) (*Target, error) {
	c, err := r.bootstrapClient()
	if err != nil {
		return nil, err
	}

	err = c.Update()
	if err != nil {
		if err, ok := err.(signed.ErrExpired); ok {
			return nil, ErrExpired{err}
		}
		return nil, err
	}

	meta, err := c.TargetMeta(name)
	if meta == nil {
		return nil, fmt.Errorf("No trust data for %s", name)
	} else if err != nil {
		return nil, err
	}

	return &Target{Name: name, Hashes: meta.Hashes, Length: meta.Length}, nil
}

// GetChangelist returns the list of the repository's unpublished changes
func (r *NotaryRepository) GetChangelist() (changelist.Changelist, error) {
	changelistDir := filepath.Join(r.tufRepoPath, "changelist")
	cl, err := changelist.NewFileChangelist(changelistDir)
	if err != nil {
		logrus.Debug("Error initializing changelist")
		return nil, err
	}
	return cl, nil
}

// Publish pushes the local changes in signed material to the remote notary-server
// Conceptually it performs an operation similar to a `git rebase`
func (r *NotaryRepository) Publish() error {
	var updateRoot bool
	var root *data.Signed
	// attempt to initialize the repo from the remote store
	c, err := r.bootstrapClient()
	if err != nil {
		if _, ok := err.(store.ErrMetaNotFound); ok {
			// if the remote store return a 404 (translated into ErrMetaNotFound),
			// the repo hasn't been initialized yet. Attempt to load it from disk.
			err := r.bootstrapRepo()
			if err != nil {
				// Repo hasn't been initialized, It must be initialized before
				// it can be published. Return an error and let caller determine
				// what it wants to do.
				logrus.Debug(err.Error())
				logrus.Debug("Repository not initialized during Publish")
				return &ErrRepoNotInitialized{}
			}
			// We had local data but the server doesn't know about the repo yet,
			// ensure we will push the initial root file
			root, err = r.tufRepo.Root.ToSigned()
			if err != nil {
				return err
			}
			updateRoot = true
		} else {
			// The remote store returned an error other than 404. We're
			// unable to determine if the repo has been initialized or not.
			logrus.Error("Could not publish Repository: ", err.Error())
			return err
		}
	} else {
		// If we were successfully able to bootstrap the client (which only pulls
		// root.json), update it the rest of the tuf metadata in preparation for
		// applying the changelist.
		err = c.Update()
		if err != nil {
			if err, ok := err.(signed.ErrExpired); ok {
				return ErrExpired{err}
			}
			return err
		}
	}
	cl, err := r.GetChangelist()
	if err != nil {
		return err
	}
	// apply the changelist to the repo
	err = applyChangelist(r.tufRepo, cl)
	if err != nil {
		logrus.Debug("Error applying changelist")
		return err
	}

	// check if our root file is nearing expiry. Resign if it is.
	if nearExpiry(r.tufRepo.Root) || r.tufRepo.Root.Dirty {
		if err != nil {
			return err
		}
		root, err = r.tufRepo.SignRoot(data.DefaultExpires("root"))
		if err != nil {
			return err
		}
		updateRoot = true
	}
	// we will always resign targets and snapshots
	targets, err := r.tufRepo.SignTargets("targets", data.DefaultExpires("targets"))
	if err != nil {
		return err
	}
	snapshot, err := r.tufRepo.SignSnapshot(data.DefaultExpires("snapshot"))
	if err != nil {
		return err
	}

	remote, err := getRemoteStore(r.baseURL, r.gun, r.roundTrip)
	if err != nil {
		return err
	}

	// ensure we can marshal all the json before sending anything to remote
	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		return err
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	update := make(map[string][]byte)
	// if we need to update the root, marshal it and push the update to remote
	if updateRoot {
		rootJSON, err := json.Marshal(root)
		if err != nil {
			return err
		}
		update["root"] = rootJSON
	}
	update["targets"] = targetsJSON
	update["snapshot"] = snapshotJSON
	err = remote.SetMultiMeta(update)
	if err != nil {
		return err
	}
	err = cl.Clear("")
	if err != nil {
		// This is not a critical problem when only a single host is pushing
		// but will cause weird behaviour if changelist cleanup is failing
		// and there are multiple hosts writing to the repo.
		logrus.Warn("Unable to clear changelist. You may want to manually delete the folder ", filepath.Join(r.tufRepoPath, "changelist"))
	}
	return nil
}

func (r *NotaryRepository) bootstrapRepo() error {
	kdb := keys.NewDB()
	tufRepo := tuf.NewRepo(kdb, r.CryptoService)

	logrus.Debugf("Loading trusted collection.")
	rootJSON, err := r.fileStore.GetMeta("root", 0)
	if err != nil {
		return err
	}
	root := &data.SignedRoot{}
	err = json.Unmarshal(rootJSON, root)
	if err != nil {
		return err
	}
	err = tufRepo.SetRoot(root)
	if err != nil {
		return err
	}
	targetsJSON, err := r.fileStore.GetMeta("targets", 0)
	if err != nil {
		return err
	}
	targets := &data.SignedTargets{}
	err = json.Unmarshal(targetsJSON, targets)
	if err != nil {
		return err
	}
	tufRepo.SetTargets("targets", targets)
	snapshotJSON, err := r.fileStore.GetMeta("snapshot", 0)
	if err != nil {
		return err
	}
	snapshot := &data.SignedSnapshot{}
	err = json.Unmarshal(snapshotJSON, snapshot)
	if err != nil {
		return err
	}
	tufRepo.SetSnapshot(snapshot)

	r.tufRepo = tufRepo

	return nil
}

func (r *NotaryRepository) saveMetadata() error {
	logrus.Debugf("Saving changes to Trusted Collection.")

	signedRoot, err := r.tufRepo.SignRoot(data.DefaultExpires("root"))
	if err != nil {
		return err
	}
	rootJSON, err := json.Marshal(signedRoot)
	if err != nil {
		return err
	}

	targetsToSave := make(map[string][]byte)
	for t := range r.tufRepo.Targets {
		signedTargets, err := r.tufRepo.SignTargets(t, data.DefaultExpires("targets"))
		if err != nil {
			return err
		}
		targetsJSON, err := json.Marshal(signedTargets)
		if err != nil {
			return err
		}
		targetsToSave[t] = targetsJSON
	}

	signedSnapshot, err := r.tufRepo.SignSnapshot(data.DefaultExpires("snapshot"))
	if err != nil {
		return err
	}
	snapshotJSON, err := json.Marshal(signedSnapshot)
	if err != nil {
		return err
	}

	err = r.fileStore.SetMeta("root", rootJSON)
	if err != nil {
		return err
	}

	for role, blob := range targetsToSave {
		parentDir := filepath.Dir(role)
		os.MkdirAll(parentDir, 0755)
		r.fileStore.SetMeta(role, blob)
	}

	return r.fileStore.SetMeta("snapshot", snapshotJSON)
}

func (r *NotaryRepository) bootstrapClient() (*tufclient.Client, error) {
	var rootJSON []byte
	remote, err := getRemoteStore(r.baseURL, r.gun, r.roundTrip)
	if err == nil {
		// if remote store successfully set up, try and get root from remote
		rootJSON, err = remote.GetMeta("root", maxSize)
	}

	// if remote store couldn't be setup, or we failed to get a root from it
	// load the root from cache (offline operation)
	if err != nil {
		if err, ok := err.(store.ErrMetaNotFound); ok {
			// if the error was MetaNotFound then we successfully contacted
			// the store and it doesn't know about the repo.
			return nil, err
		}
		result, cacheErr := r.fileStore.GetMeta("root", maxSize)
		if cacheErr != nil {
			// if cache didn't return a root, we cannot proceed - just return
			// the original error.
			return nil, err
		}
		rootJSON = result
		logrus.Debugf(
			"Using local cache instead of remote due to failure: %s", err.Error())
	}
	// can't just unmarshal into SignedRoot because validate root
	// needs the root.Signed field to still be []byte for signature
	// validation
	root := &data.Signed{}
	err = json.Unmarshal(rootJSON, root)
	if err != nil {
		return nil, err
	}

	err = r.CertManager.ValidateRoot(root, r.gun)
	if err != nil {
		return nil, err
	}

	kdb := keys.NewDB()
	r.tufRepo = tuf.NewRepo(kdb, r.CryptoService)

	signedRoot, err := data.RootFromSigned(root)
	if err != nil {
		return nil, err
	}
	err = r.tufRepo.SetRoot(signedRoot)
	if err != nil {
		return nil, err
	}

	return tufclient.NewClient(
		r.tufRepo,
		remote,
		kdb,
		r.fileStore,
	), nil
}

// RotateKeys removes all existing keys associated with role and adds
// the keys specified by keyIDs to the role. These changes are staged
// in a changelist until publish is called.
func (r *NotaryRepository) RotateKeys() error {
	for _, role := range []string{"targets", "snapshot"} {
		key, err := r.CryptoService.Create(role, data.ECDSAKey)
		if err != nil {
			return err
		}
		err = r.rootFileKeyChange(role, changelist.ActionCreate, key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *NotaryRepository) rootFileKeyChange(role, action string, key data.PublicKey) error {
	cl, err := changelist.NewFileChangelist(filepath.Join(r.tufRepoPath, "changelist"))
	if err != nil {
		return err
	}
	defer cl.Close()

	kl := make(data.KeyList, 0, 1)
	kl = append(kl, key)
	meta := changelist.TufRootData{
		RoleName: role,
		Keys:     kl,
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	c := changelist.NewTufChange(
		action,
		changelist.ScopeRoot,
		changelist.TypeRootRole,
		role,
		metaJSON,
	)
	err = cl.Add(c)
	if err != nil {
		return err
	}
	return nil
}
