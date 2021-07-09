package grpckeystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
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
	logrus.Debugf("grpc key store: invalid private key access attempt for key: %s", g.ID())
	return nil
}

// SignatureAlgorithm is a required method of the data.PrivateKey interface.
func (g GRPCPrivateKey) SignatureAlgorithm() data.SigAlgorithm {
	// SignatureAlgorithm returns the signing algorithm as identified by
	// during AddKey or GenerateKey
	return data.SigAlgorithm(g.signatureAlgorithm)
}

// DefaultDialTimeout controls the initial connection timeout with the
// server.  If a grpckeystore server is configured, but not accessible,
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
			"grpc key store: configure both tls_client_cert and tls_client_key, or neither")
	}

	if ca == "" {
		return nil, fmt.Errorf(
			"grpc key store: root_ca configuration required")
	}

	// set up client auth if configured
	if cert != "" {
		// Load the client certificates from disk
		certificate, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("grpc key store: could not load tls_client_cert file: %s", err)
		}
		certificates = append(certificates, certificate)
	}

	// set up the CA, if configured
	if ca != "" {
		// Create a certificate pool from the certificate authority
		certPool = x509.NewCertPool()
		calist, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("grpc key store: could not load root_ca file: %s", err)
		}

		// Append the certificates from the CA
		if ok := certPool.AppendCertsFromPEM(calist); !ok {
			return nil, fmt.Errorf("grpc key store: failed to append ca certs in root_ca file")
		}
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: certificates,
		RootCAs:      certPool,
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

// parseECDSASignature accepts a raw R,S concatenated format or ASN.1 encoded
// ECDSA signature and normalizes it to the raw R,S concatenated together format
// that the verifiers want to see.  If useful in other cases, perhaps eventually
// move to utils/pkcs8.go?
func parseECDSASignature(signatureBytes []byte, pubKeyBytes []byte) ([]byte, error) {

	// an ECDSA signature can be expressed several ways:
	//
	// 1) the raw format where R,S are concatenated together
	//
	// 2) ASN.1 encoded in RFC-3279 sec 2.2.3 format:
	//
	// SEQUENCE {
	//      INTEGER
	//      INTEGER
	//   }
	//
	// 3) ASN.1 encoded with in RFC-3279 sec 2.2.3 format wrapped by an OID
	// SEQUENCE {
	//     OBJECTIDENTIFIER   (e.g. 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
	//       BITSTRING
	//     }
	//
	//  where the BITSTRING is an ASN.1 encoded signature in format 2
	//
	//  since the verifier wants the raw format (format 1), all received
	//  ECDSA signature variants will be normalized to this format

	// First determine the expected raw format length of a good signature.
	// Parsing the public key will give this info.
	pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("grpc key store: ecdsa signature parser failed to parse public key: %s", err)
	}

	edcsapub := pub.(*ecdsa.PublicKey)
	octetLength := (edcsapub.Params().BitSize + 7) >> 3
	expectedRawSigLen := octetLength * 2

	// check to see if we already have the expected raw signature length
	if len(signatureBytes) == expectedRawSigLen {
		// signature is already in the raw format that the verifier wants
		return signatureBytes, nil
	}

	// Test Signature is too short error
	if len(signatureBytes) < expectedRawSigLen {
		return nil, fmt.Errorf("grpc key store: ecdsa signature too short for public key")
	}

	// At this point, the signature is longer than the normalized format, so
	// it must be either ASN.1 encoded or invalid

	// try to parse the signature looking for an OID (format #3).
	// if this succeeds, we'll still need to parse the format #2 portion.  If
	// it fails, it's OK, we might have just been given format #2 to begin with.
	type ecdsaSigWithObjectID struct {
		Oid asn1.ObjectIdentifier
		S   asn1.BitString
	}
	var ecdsasigOID ecdsaSigWithObjectID
	_, err = asn1.Unmarshal(signatureBytes, &ecdsasigOID)

	// if asn.1 decoding for OID format (format #3) succeeded, update signature
	// bytes to only include the format #2 part
	if err == nil {
		signatureBytes = ecdsasigOID.S.Bytes
	}

	// Attempt to parse as ASN.1 encoded in RFC-3279 sec 2.2.3 (format 2)
	type ecdsaSig struct {
		R *big.Int
		S *big.Int
	}
	var ecdsasig ecdsaSig
	_, err = asn1.Unmarshal(signatureBytes, &ecdsasig)

	// if asn.1 decoding succeeded, get the signature bytes
	if err == nil {
		rBytes, sBytes := ecdsasig.R.Bytes(), ecdsasig.S.Bytes()

		// MUST include leading zeros in the output
		rBuf := make([]byte, octetLength-len(rBytes), octetLength)
		sBuf := make([]byte, octetLength-len(sBytes), octetLength)
		rBuf = append(rBuf, rBytes...)
		sBuf = append(sBuf, sBytes...)
		return append(rBuf, sBuf...), nil
	}

	// exhausted the formats we understand
	return nil, fmt.Errorf("pkcs8: failed to parse ecdsa signature")
}

// The following methods implement the PrivateKey inteface

// GenerateKey requests that the keystore internally generate a key.
func (s *GRPCKeyStore) GenerateKey(keyInfo trustmanager.KeyInfo) (data.PrivateKey, error) {

	logrus.Debugf("grpc key store: generate key request for role:%s gun:%s ", keyInfo.Role, keyInfo.Gun)

	req := &GenerateKeyReq{
		Gun:  string(keyInfo.Gun),
		Role: string(keyInfo.Role),
	}
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	rsp, err := s.client.GenerateKey(ctx, req)

	if err != nil {
		logrus.Debugf("grpc key store: generate key RPC failed: %s", err)
		return nil, fmt.Errorf("grpc key store: generate key RPC failed: %s", err)
	}

	// The public key returned from the GRPC keystore is expected
	// to be ASN.1 DER encoded.  The key type is imbedded in the encoding
	pubKey, err := utils.ParsePublicKey(rsp.PublicKey)
	if err != nil {
		logrus.Debugf("grpc key store unable to parse public key: %s", err)
		return nil, fmt.Errorf("grpc key store unable to parse public key: %s", err)
	}
	privKey := NewGRPCPrivateKey(rsp.RemoteKeyId, rsp.SignatureAlgorithm, s, pubKey)
	if privKey == nil {
		logrus.Debug("grpc key store: GenerateKey failed to initialize new key")
		return nil, fmt.Errorf("grpc key store: GenerateKey failed to initialize new key")
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
		logrus.Debugf("grpc key store: AssociateKey RPC failed: %s", err)
		return nil, fmt.Errorf("grpc key store: AssociateKey RPC failed: %s", err)
	}

	s.keys[privKey.ID()] = GRPCKey{
		gun:         keyInfo.Gun,
		role:        keyInfo.Role,
		remoteKeyID: rsp.RemoteKeyId,
	}

	logrus.Debug("grpc key store: GenerateKey/AssociateKey successful")
	return privKey, nil
}

// AddKey stores the contents of private key
func (s *GRPCKeyStore) AddKey(keyInfo trustmanager.KeyInfo, privKey data.PrivateKey) error {

	logrus.Debugf("grpc key store: AddKey invoked for role:%s gun:%s ", keyInfo.Role, keyInfo.Gun)

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
		logrus.Debugf("grpc key store: AddKey RPC failed: %s", err)
		return fmt.Errorf("grpc key store: AddKey RPC failed: %s", err)
	}

	s.keys[privKey.ID()] = GRPCKey{
		gun:         keyInfo.Gun,
		role:        keyInfo.Role,
		remoteKeyID: rsp.RemoteKeyId,
	}

	logrus.Debugf("grpc key store: add key successful")
	return nil
}

// GetKey returns the Pseudo PrivateKey given a KeyID
func (s *GRPCKeyStore) GetKey(keyID string) (data.PrivateKey, data.RoleName, error) {

	logrus.Debugf("grpc key store: GetKey called for keyId: %s", keyID)
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
		logrus.Debugf("grpc key store: GetKey RPC failed: %s", err)
		return nil, "", fmt.Errorf("grpc key store: GetKey RPC failed: %s", err)
	}

	// The public key returned from the GRPC keystore is expected
	// to be ASN.1 DER encoded.  That means the key type is imbedded in the
	// encoding.  ParsePublicKey will figure out the type
	pubKey, err := utils.ParsePublicKey(rsp.PublicKey)
	if err != nil {
		logrus.Debugf("grpc key store: GetKey failed to parse public key: %s", err)
		return nil, "", fmt.Errorf("grpc key store: get key failed to parse public key: %s", err)
	}
	privKey := NewGRPCPrivateKey(key.remoteKeyID, rsp.SignatureAlgorithm, s, pubKey)
	if privKey == nil {
		logrus.Debug("grpc key store: GetKey failed to initialize key")
		return nil, "", fmt.Errorf("GRPCKeystore GetKey failed to initialize key")
	}
	logrus.Debugf("grpc key store: GetKey succeeded for role: %s", rsp.Role)
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

	logrus.Debugf("grpc key store: GetKeyInfo called for keyId: %s", keyID)

	key, ok := s.keys[keyID]
	if !ok {
		logrus.Debugf("grpc key store: GetKeyInfo could not find keyId: %s", keyID)
		return trustmanager.KeyInfo{}, fmt.Errorf("grpc key store: GetKeyInfo could not find keyId: %s", keyID)
	}
	return trustmanager.KeyInfo{Role: key.role, Gun: key.gun}, nil
}

// ListKeys returns a list of unique PublicKeys present on the KeyFileStore,
// by returning a copy of the keyInfoMap if it exists.
func (s *GRPCKeyStore) ListKeys() map[string]trustmanager.KeyInfo {

	logrus.Debug("grpc key store: ListKeys invoked")

	if len(s.keys) > 0 {
		logrus.Debugf("grpc key store: ListKeys returning cashed list of %d keys", len(s.keys))
		return buildKeyMap(s.keys)
	}

	keys := make(map[string]GRPCKey)

	req := &ListKeysReq{}
	ctx, cancel := s.getContext()
	ctx = metadata.NewContext(ctx, s.metadata)
	defer cancel()
	rsp, err := s.client.ListKeys(ctx, req)

	if err != nil {
		logrus.Debugf("grpc key store: ListKeys RPC failed: %s", err)
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
	logrus.Debugf("grpc key store: ListKeys succeeded, returned %d keys", len(keys))
	return buildKeyMap(keys)
}

// RemoveKey removes the key from the keyfilestore
func (s *GRPCKeyStore) RemoveKey(keyID string) error {

	logrus.Debugf("grpc key store: RemoveKey called for keyId: %s", keyID)
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
		logrus.Debugf("grpc key store: RemoveKey RPC failed: %s", err)
		return fmt.Errorf("grpc key store: RemoveKey RPC failed: %s", err)
	}

	// remove key from the keymap
	delete(s.keys, keyID)

	logrus.Debugf("grpc key store: RemoveKey succeeded for keyId: %s", keyID)
	return nil

}

// Sign is a required method of the crypto.Signer interface and the data.PrivateKey
// interface
func (g *GRPCPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {

	logrus.Debugf("grpc key store: Sign invoked for keyid: %s", g.ID())
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
		logrus.Debugf("grpc key store: Sign failed: %s", err)
		return nil, fmt.Errorf("grpc key store: Sign failed: %s", err)
	}

	switch g.SignatureAlgorithm() {
	case data.ECDSASignature:
		{
			// the EDCSA signature from the keystore may be either asn.1 encoded or
			// raw (i.e. just R,S concatenated together). ParseECDSASignature will
			// automatically normalize either type to the the raw R,S format that the verifier
			// expects.
			sig, err = parseECDSASignature(rsp.Signature, g.Public())
			if err != nil {
				logrus.Debugf("grpc key store: ecdsa signature error: %s", err)
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
			// the RSA signature returned from the keystore is always expected to be
			// asn.1 encoded signature.  The signature verifier handles this natively
			sig = rsp.Signature
		}
	default:
		logrus.Debugf("grpc key store: unsupported SignatureAlgorithm: %s", g.SignatureAlgorithm())
		return nil, fmt.Errorf("grpc key store: unsupported SignatureAlgorithm: %s", g.SignatureAlgorithm())
	}

	// attempt to verify signature
	v := signed.Verifiers[g.SignatureAlgorithm()]
	err = v.Verify(g.PublicKey, sig, msg)
	if err != nil {
		logrus.Debugf("grpc key store: signature verification error: %s", err)
		return nil, fmt.Errorf("grpc key store: signature verification error: %s", err)
	}

	return sig, nil
}
