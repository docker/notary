package grpckeystore

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
	"github.com/theupdateframework/notary/tuf/utils"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// GRPCKeyStore is a wrapper around the GRPC client, translating between
// the Go and GRPC APIs.
type GRPCKeyStore struct {
	client     GRPCKeyStoreClient
	clientConn *grpc.ClientConn
	location   string
	timeout    time.Duration
	keys       map[string]GRPCKey
	metadata   metadata.MD
}

// GRPCKey represents a remote key stored in the local key map
type GRPCKey struct {
	keyID       string
	remoteKeyID string
	gun         data.GUN
	role        data.RoleName
}

// GRPCPrivateKey represents a private key from the remote key store
type GRPCPrivateKey struct {
	data.PublicKey
	remoteKeyID        string
	store              *GRPCKeyStore
	signatureAlgorithm string
}

// GRPCkeySigner wraps a GRPCPrivateKey and implements the crypto.Signer interface
type GRPCkeySigner struct {
	GRPCPrivateKey
}

// GRPCClientConfig is all the configuration elements relating to
// the GRPC key store server
type GRPCClientConfig struct {
	Server          string
	TLSCertFile     string
	TLSKeyFile      string
	TLSCAFile       string
	DialTimeout     time.Duration
	BlockingTimeout time.Duration
	Metadata        metadata.MD
}

// NewGRPCPrivateKey returns a GRPCPrivateKey, which implements the data.PrivateKey
// interface except that the private material is inaccessible
func NewGRPCPrivateKey(remoteID string, signatureAlgorithm string, store *GRPCKeyStore, pubKey data.PublicKey) *GRPCPrivateKey {

	return &GRPCPrivateKey{
		PublicKey:          pubKey,
		remoteKeyID:        remoteID,
		store:              store,
		signatureAlgorithm: signatureAlgorithm,
	}
}

// Public is a required method of the crypto.Signer interface
func (gs *GRPCkeySigner) Public() crypto.PublicKey {
	publicKey, err := x509.ParsePKIXPublicKey(gs.GRPCPrivateKey.Public())
	if err != nil {
		return nil
	}
	return publicKey
}

// CryptoSigner is a required method of the data.PrivateKey interfacere.
// Returns a crypto.Signer that wraps the GRPCPrivateKey. Needed for
// Certificate generation only.
func (g *GRPCPrivateKey) CryptoSigner() crypto.Signer {
	return &GRPCkeySigner{GRPCPrivateKey: *g}
}

// Private is a required method of the data.PrivateKey interface
// it is not used for the GRPC key store store case
func (g *GRPCPrivateKey) Private() []byte {
	// We cannot return the private key from the remote store
	logrus.Debugf("GRPCkeystore: Invalid private key access attempt for key: %s", g.ID())
	return nil
}

// SignatureAlgorithm is a required method of the data.PrivateKey interface.
func (g GRPCPrivateKey) SignatureAlgorithm() data.SigAlgorithm {
	// SignatureAlgorithm returns the signing algorithm as identified by
	// during AddKey or GenerateKey
	return data.SigAlgorithm(g.signatureAlgorithm)
}

// DefaultDialTimeout controls the initial connection timeout with the
// server.  If a grpckeystore server is configured, but not accessable,
// notary keystore initialization will be delayed by this value
const DefaultDialTimeout = time.Second * 5

// DefaultBlockingTimeout is the time a request will block waiting
// for a response from the server if no other timeout is configured.
const DefaultBlockingTimeout = time.Second * 30

// GetGRPCCredentials takes a client configuration and returns
// the corresponding TransportCredentials for the GRPC connection
func GetGRPCCredentials(config *GRPCClientConfig) (credentials.TransportCredentials, error) {

	var certPool *x509.CertPool
	var certificates []tls.Certificate

	cert := config.TLSCertFile
	key := config.TLSKeyFile
	ca := config.TLSCAFile

	if (cert == "" && key != "") || (cert != "" && key == "") {
		return nil, fmt.Errorf(
			"GRPC KeyStore Config Error: configure both tls_client_cert and tls_client_key, or neither")
	}

	if cert != "" && key != "" && ca == "" {
		return nil, fmt.Errorf(
			"GRPC KeyStore Config Error: root_ca required when tls_client_cert and tls_client_key are configured")
	}

	// set up client auth if configured
	if cert != "" {
		// Load the client certificates from disk
		certificate, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("GRPC KeyStore Config Error: could not load tls_client_cert file: %s", err)
		}
		certificates = append(certificates, certificate)
	}

	// set up the CA, if configured
	if ca != "" {
		// Create a certificate pool from the certificate authority
		certPool = x509.NewCertPool()
		calist, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("GRPC KeyStore Config Error: could not load root_ca file: %s", err)
		}

		// Append the certificates from the CA
		if ok := certPool.AppendCertsFromPEM(calist); !ok {
			return nil, fmt.Errorf("GRPC KeyStore Config Error: failed to append ca certs in root_ca file")
		}
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates:       certificates,
		InsecureSkipVerify: (ca == ""),
		RootCAs:            certPool,
	})

	return creds, nil
}

// NewGRPCKeyStore creates a GRPCKeyStore Client
func NewGRPCKeyStore(config *GRPCClientConfig) (*GRPCKeyStore, error) {

	var err error

	if config.DialTimeout == 0 {
		config.DialTimeout = DefaultDialTimeout
	}

	if config.BlockingTimeout == 0 {
		config.BlockingTimeout = DefaultBlockingTimeout
	}

	transportCredentials, err := GetGRPCCredentials(config)
	if err != nil {
		return nil, err
	}

	cc, err := grpc.Dial(
		config.Server,
		grpc.WithTransportCredentials(transportCredentials),
		grpc.WithBlock(),
		grpc.WithTimeout(config.DialTimeout),
	)

	if err != nil {
		return nil, err
	}

	ks := &GRPCKeyStore{
		client:     NewGRPCKeyStoreClient(cc),
		clientConn: cc,
		location:   config.Server,
		timeout:    config.BlockingTimeout,
		metadata:   config.Metadata,
		keys:       make(map[string]GRPCKey),
	}

	return ks, nil
}

// Name returns a user friendly name for the location this store
// keeps its data
func (s *GRPCKeyStore) Name() string {
	return "GRPC remote store"
}

// getContext returns a context with the timeout configured at initialization
// time of the RemoteStore.
func (s *GRPCKeyStore) getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

// Location returns a human readable indication of where the storage is located.
func (s *GRPCKeyStore) Location() string {
	return fmt.Sprintf("Remote GRPC Key Store @ %s", s.location)
}

// Close the client grpc connection
func (s *GRPCKeyStore) closeClient() {
	if s.clientConn != nil {
		s.clientConn.Close()
	}
	return
}

// The following methods implement the PrivateKey inteface

// GenerateKey requests that the keystore internally generate a key.
func (s *GRPCKeyStore) GenerateKey(keyInfo trustmanager.KeyInfo) (data.PrivateKey, error) {

	logrus.Debugf("GRPCKeystore GenerateKey request for role:%s gun:%s ", keyInfo.Role, keyInfo.Gun)

	// We only support generating root and targets keys for now
	if (keyInfo.Role != data.CanonicalRootRole) && (keyInfo.Role != data.CanonicalTargetsRole) {
		logrus.Debugf("GRPCKeystore GenerateKey supports root and targets role, requested role:%s", keyInfo.Role)
		return nil, fmt.Errorf("GRPC keystore only supports generating root/target keys, got role %s", keyInfo.Role)
	}

	req := &GenerateKeyReq{
		Gun:  string(keyInfo.Gun),
		Role: string(keyInfo.Role),
	}
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	rsp, err := s.client.GenerateKey(ctx, req)

	if err != nil {
		logrus.Debugf("GRPCKeystore GenerateKey RPC Failed: %s", err)
		return nil, fmt.Errorf("GRPCKeystore GenerateKey RPC Failed: %s", err)
	}

	// The public key returned from the GRPC keystore is expected
	// to be ASN.1 DER encoded.  The key type is imbedded in the encoding
	pubKey, err := utils.ParsePublicKey(rsp.PublicKey)
	if err != nil {
		logrus.Debugf("GRPCKeystore ParsePublicKey failed: %s", err)
		return nil, fmt.Errorf("GRPCKeystore ParsePublicKey failed: %s", err)
	}
	privKey := NewGRPCPrivateKey(rsp.RemoteKeyId, rsp.SignatureAlgorithm, s, pubKey)
	if privKey == nil {
		logrus.Debug("GRPCKeystore GenerateKey failed to initialize new key")
		return nil, fmt.Errorf("GRPCKeystore GenerateKey failed to initialize new key")
	}

	akreq := &AssociateKeyReq{
		KeyId:       privKey.ID(),
		RemoteKeyId: privKey.remoteKeyID,
	}

	ctx, cancel = s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	_, err = s.client.AssociateKey(ctx, akreq)

	if err != nil {
		logrus.Debugf("GRPCKeystore AssociateKey RPC Failed: %s", err)
		return nil, fmt.Errorf("GRPCKeystore AssociateKey RPC Failed: %s", err)
	}

	s.keys[privKey.ID()] = GRPCKey{
		gun:         keyInfo.Gun,
		role:        keyInfo.Role,
		remoteKeyID: rsp.RemoteKeyId,
	}

	logrus.Debug("GRPC GenerateKey (GenerateKey/AssociateKey) Succeeded")
	return privKey, nil
}

// AddKey stores the contents of private key
func (s *GRPCKeyStore) AddKey(keyInfo trustmanager.KeyInfo, privKey data.PrivateKey) error {

	logrus.Debugf("GRPCKeystore AddKey invoked for role:%s gun:%s ", keyInfo.Role, keyInfo.Gun)

	req := &AddKeyReq{
		KeyId:              privKey.ID(),
		Gun:                string(keyInfo.Gun),
		Role:               string(keyInfo.Role),
		Algorithm:          string(privKey.Algorithm()),
		SignatureAlgorithm: string(privKey.SignatureAlgorithm()),
		PublicKey:          privKey.Public(),
		PrivateKey:         privKey.Private(),
	}
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	rsp, err := s.client.AddKey(ctx, req)

	if err != nil {
		logrus.Debugf("GRPCkeystore AddKey RPC Operation Failed: %s", err)
		return fmt.Errorf("GRPC AddKey error: %s", err)
	}

	s.keys[privKey.ID()] = GRPCKey{
		gun:         keyInfo.Gun,
		role:        keyInfo.Role,
		remoteKeyID: rsp.RemoteKeyId,
	}

	logrus.Debugf("GRPCkeystore AddKey Operation Succeeded")
	return nil
}

// GetKey returns the Pseudo PrivateKey given a KeyID
func (s *GRPCKeyStore) GetKey(keyID string) (data.PrivateKey, data.RoleName, error) {

	logrus.Debugf("GRPCkeystore GetKey operation called for keyId: %s", keyID)
	key, ok := s.keys[keyID]
	if !ok {
		return nil, "", trustmanager.ErrKeyNotFound{KeyID: keyID}
	}

	req := &GetKeyReq{
		KeyId:       keyID,
		RemoteKeyId: key.remoteKeyID,
	}
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	rsp, err := s.client.GetKey(ctx, req)

	if err != nil {
		logrus.Debugf("GRPCkeystore GetKey RPC Operation Failed: %s", err)
		return nil, "", fmt.Errorf("GRPC GetKey error: %s", err)
	}

	// The public key returned from the GRPC keystore is expected
	// to be ASN.1 DER encoded.  That means the key type is imbedded in the
	// encoding.  ParsePublicKey will figure out the type
	pubKey, err := utils.ParsePublicKey(rsp.PublicKey)
	if err != nil {
		logrus.Debugf("GRPCKeystore GetKey ParsePublicKey failed: %s", err)
		return nil, "", fmt.Errorf("GRPCKeystore GetKey ParsePublicKey failed: %s", err)
	}
	privKey := NewGRPCPrivateKey(key.remoteKeyID, rsp.SignatureAlgorithm, s, pubKey)
	if privKey == nil {
		logrus.Debug("GRPCKeystore GetKey failed to initialize key")
		return nil, "", fmt.Errorf("GRPCKeystore GetKey failed to initialize key")
	}
	logrus.Debugf("GRPC GetKey operation succeeded for role: %s", rsp.Role)
	return privKey, data.RoleName(rsp.Role), err
}

func buildKeyMap(keys map[string]GRPCKey) map[string]trustmanager.KeyInfo {
	res := make(map[string]trustmanager.KeyInfo)
	for k, v := range keys {
		res[k] = trustmanager.KeyInfo{Role: v.role, Gun: v.gun}
	}
	return res
}

// GetKeyInfo returns the corresponding gun and role key info for a keyID
// Note that this method does not map to a GRPC call.  The local information
// from the key dictionary is returned, as it will match the GRPC data.
func (s *GRPCKeyStore) GetKeyInfo(keyID string) (trustmanager.KeyInfo, error) {

	logrus.Debugf("GRPCkeystore GetKeyInfo operation called for keyId: %s", keyID)

	key, ok := s.keys[keyID]
	if !ok {
		logrus.Debugf("GRPCkeystore GetKeyInfo could not find info: %s", keyID)
		return trustmanager.KeyInfo{}, fmt.Errorf("Could not find info for keyID %s", keyID)
	}
	return trustmanager.KeyInfo{Role: key.role, Gun: key.gun}, nil
}

// ListKeys returns a list of unique PublicKeys present on the KeyFileStore,
// by returning a copy of the keyInfoMap if it exists.
func (s *GRPCKeyStore) ListKeys() map[string]trustmanager.KeyInfo {

	logrus.Debug("GRPCkeystore ListKeys operation invoked")

	if len(s.keys) > 0 {
		logrus.Debugf("GRPCkeystore ListKeys returning cashed list of %d keys", len(s.keys))
		return buildKeyMap(s.keys)
	}

	keys := make(map[string]GRPCKey)

	req := &ListKeysReq{}
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	rsp, err := s.client.ListKeys(ctx, req)

	if err != nil {
		logrus.Debugf("GRPCkeystore ListKeys RPC Operation Failed: %s", err)
		// return a blank list...
		return buildKeyMap(keys)
	}

	rspkeys := rsp.GetKeyData()
	if len(rspkeys) > 0 {
		for _, ki := range rspkeys {
			keys[ki.GetKeyId()] = GRPCKey{
				gun:         data.GUN(ki.GetGun()),
				role:        data.RoleName(ki.GetRole()),
				remoteKeyID: ki.GetRemoteKeyId(),
			}
		}
	}
	// save the results into the local list
	s.keys = keys
	logrus.Debugf("GRPCKeystore ListKeys succeeded, returned %d keys", len(keys))
	return buildKeyMap(keys)
}

// RemoveKey removes the key from the keyfilestore
func (s *GRPCKeyStore) RemoveKey(keyID string) error {

	logrus.Debugf("GRPCkeystore RemoveKey operation called for keyId: %s", keyID)
	key, ok := s.keys[keyID]
	if !ok {
		return trustmanager.ErrKeyNotFound{KeyID: keyID}
	}

	req := &RemoveKeyReq{
		KeyId:       keyID,
		RemoteKeyId: key.remoteKeyID,
	}
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	_, err := s.client.RemoveKey(ctx, req)

	if err != nil {
		logrus.Debugf("GRPCkeystore RemoveKey RPC Operation Failed: %s", err)
		return fmt.Errorf("GRPC RemoveKey error: %s", err)
	}

	// remove key from the keymap
	delete(s.keys, keyID)

	logrus.Debugf("GRPC RemoveKey succeeded for keyId: %s", keyID)
	return nil

}

// Sign is a required method of the crypto.Signer interface and the data.PrivateKey
// interface
func (g *GRPCPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {

	logrus.Debugf("GRPCkeystore Sign invoked for keyid: %s", g.ID())
	var sig []byte

	// Hash algorithm needs to match the verifiers, which are hardcoded SHA256
	//  currently. We expect notary server to both hash (and in the RSA case, pad)
	// to calculate the proper signature.
	hashAlgorithm := notary.SHA256

	req := &SignReq{
		KeyId:         g.ID(),
		RemoteKeyId:   g.remoteKeyID,
		HashAlgorithm: hashAlgorithm,
		Message:       msg,
	}

	s := g.store
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	rsp, err := s.client.Sign(ctx, req)

	if err != nil {
		logrus.Debugf("GRPCkeystore Sign failed: %s", err)
		return nil, fmt.Errorf("GRPC Sign failed: %s", err)
	}

	switch g.SignatureAlgorithm() {
	case data.ECDSASignature:
		{
			// the EDCSA signature from the keystore may be either asn.1 encoded or
			// raw (i.e. just R,S concatenated together). ParseECDSASignature will
			// automatically normalize either type to the the raw R,S format that the verifier
			// expects.
			sig, err = utils.ParseECDSASignature(rsp.Signature, g.Public())
			if err != nil {
				logrus.Debugf("GRPCkeystore Signature error: %s", err)
				return nil, err
			}
		}
	case data.EDDSASignature:
		{
			// Go's asn.1/x.509 don't yet support parsing an EDDSA asn.1 encoded
			// signature, so currently the only accepted format is the raw signature
			// (i.e. not ASN.1 encoded)
			sig = rsp.Signature
		}
	case data.RSAPSSSignature, data.RSAPKCS1v15Signature:
		{
			// the RSA signature returned from the keystore is always expected to be an asn.1
			// encoded signature.  Notary's signature verifier handle this format
			// natively.
			sig = rsp.Signature
		}
	default:
		logrus.Debugf("GRPCkeystore unsupported SignatureAlgorithm: %s", g.SignatureAlgorithm())
		return nil, fmt.Errorf("GRPCkeystore unsupported SignatureAlgorithm: %s", g.SignatureAlgorithm())
	}

	// attempt to verify signature
	v := signed.Verifiers[g.SignatureAlgorithm()]
	err = v.Verify(g.PublicKey, sig, msg)
	if err != nil {
		logrus.Debugf("GRPCkeystore Signature verification error: %s", err)
		return nil, fmt.Errorf("GRPC signature verfication error: %s", err)
	}

	return sig, nil
}
