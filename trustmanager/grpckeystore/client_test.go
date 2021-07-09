package grpckeystore

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
	testutils "github.com/theupdateframework/notary/tuf/testutils/keys"
	"github.com/theupdateframework/notary/tuf/utils"
)

// testKeyData is the structure that allows the test harness to verify
// the key data exchanged across the GRPC connection during these tests.
// server and client both have a copy of this information before the test starts
type testKeyData struct {
	keyInfo     trustmanager.KeyInfo
	privateKey  data.PrivateKey
	remoteKeyID string
	associated  bool
}

// setupTestKey creates a ECDSA, RSA, or ED25519 key for testing.  The key can then
// be used for all test operations including signing.
func setupTestKey(t *testing.T, tks *map[string]testKeyData, keyName string,
	keyType string, role data.RoleName, gun string,
	associated bool) (err error) {

	var testKeys = *tks
	var tkd testKeyData
	tkd.keyInfo.Gun = data.GUN(gun)
	tkd.keyInfo.Role = role
	tkd.remoteKeyID = keyName
	// associated indicates weather or not the key is  "live" in then
	// server.  false = key must be activated by GenerateKey or AddKey before use
	// true = we are simulating the case of keys previously stored in the repo
	tkd.associated = associated
	switch keyType {
	case data.RSAKey:
		{
			// Since GenerateKey() won't generate a RSAKey, so to test RSA, use GetRSAKey.
			//  Note that GetRSAKey always returns the same key, so testing with two
			// RSA keys is not supported unless a different way to generate an RSAKey is
			// developed. (both keys would have the same KeyID)
			tkd.privateKey, err = testutils.GetRSAKey(4096)
			require.NoError(t, err)
		}
	default:
		{
			tkd.privateKey, err = utils.GenerateKey(keyType)
			require.NoError(t, err)
		}
	}
	testKeys[keyName] = tkd
	return (err)
}

// setupTestServer fires up a test GRPC key store server so the
// GRPC keystore client has something to communicate with (and can be tested)
func setupTestServer(t *testing.T, config *testServerConfig,
	testServerData *testServerData,
	testKeys map[string]testKeyData) func() {

	var opts []grpc.ServerOption

	if (config.tlsCertFile != "") && (config.tlsKeyFile != "") {
		opts = append(opts, grpc.Creds(credentials.NewTLS(getServerTLS(t, config))))
	}
	s := grpc.NewServer(opts...)
	st := newGRPCKeyStoreSrvr(t, testServerData, testKeys)
	l, err := net.Listen(
		"tcp",
		config.addr,
	)
	require.NoError(t, err)
	RegisterGRPCKeyStoreServer(s, st)
	go func() {
		err := s.Serve(l)
		// likely not a real error - most likely a timeing window on closing the server
		testLog(t, "grpc key store test server error: %s", err)
	}()
	return func() {
		// waiting 10 milliseconds in the closer function can allow the
		// client to stop before stopping server.  This can avoid a
		// "use of closed network connection" error from showing up
		// on the server.
		time.Sleep(10 * time.Millisecond)
		s.GracefulStop()
		l.Close()
	}
}

// setupClientandServerConfig helps reduce the amount of copied code in each
// test by consolidating the setup code.  It sets up one of three options:
// - server uses TLS but client doesn't verify the cert
// - server uses TLS and client verifies the server's cert
// - mutual authentication where both client and server verify each other
func setupClientandServerConfig(t *testing.T, verifyServerCert bool, mutualAuth bool) (*testServerConfig, *testServerData, *GRPCClientConfig) {
	serverTLSCertFile := ""
	serverTLSKeyFile := ""
	serverTLSCAFile := ""
	clientTLSCertFile := ""
	clientTLSKeyFile := ""
	clientTLSCAFile := ""
	addr := "localhost:9999"

	// configure the server tls files.  use a client CA Cert on the server only if
	// mutual auth is requested (server is to verify client's cert)
	serverTLSCertFile = "notary-escrow.crt"
	serverTLSKeyFile = "notary-escrow.key"
	if mutualAuth {
		serverTLSCAFile = "root-ca.crt"
	}

	// setup the grpc server config
	serverConfig := testServerConfig{
		addr:        addr,
		tlsCertFile: serverTLSCertFile,
		tlsKeyFile:  serverTLSKeyFile,
		tlsCAFile:   serverTLSCAFile,
	}

	// configure the client tls files.  use a client cert and key only when
	// mutual auth is requested.  configure the CA file when verifyServerCert
	// is requested
	certDir := getCertsDir(t)
	if mutualAuth {
		clientTLSCertFile = filepath.Join(certDir, "notary-escrow.crt")
		clientTLSKeyFile = filepath.Join(certDir, "notary-escrow.key")
	}
	if verifyServerCert {
		clientTLSCAFile = filepath.Join(certDir, "root-ca.crt")
	}

	// setup the test server's test harness data -- this controls whether the
	// server will do error injection and/or metadata verification
	testServerData := testServerData{
		injectErrorGenerateKey:  false,
		injectErrorAssociateKey: false,
		injectErrorAddKey:       false,
		injectErrorListKeys:     false,
		injectErrorGetKey:       false,
		injectErrorRemoveKey:    false,
		injectErrorSign:         false,
		injectErrorStr:          "test error string",
		metadata:                metadata.Pairs(),
	}

	// setup the grpc client config
	clientConfig := GRPCClientConfig{
		Server:          addr,
		TLSCertFile:     clientTLSCertFile,
		TLSKeyFile:      clientTLSKeyFile,
		TLSCAFile:       clientTLSCAFile,
		DialTimeout:     0,
		BlockingTimeout: 0,
		Metadata:        metadata.Pairs(),
	}

	return &serverConfig, &testServerData, &clientConfig
}

// In order to test the GRPC keystore client, we need a GRPC keystore server.
// Below is the implementation of a GRPC server testing server that allows the
//  client tests to have a GRPC server to talk to.

const testMetadataKey string = "testkey"
const testMetadataValue string = "testvalue"

// testServerConfig is the main config file for the server - it has the
// server TLS config as well as the address to listen on.
type testServerConfig struct {
	addr        string
	tlsCertFile string
	tlsKeyFile  string
	tlsCAFile   string
}

// testServerData allows the server to inject various errors, testing error
// conditions on the client.  It also allows the server to verify the metadata
// send by the client.
type testServerData struct {
	injectErrorGenerateKey  bool
	injectErrorAssociateKey bool
	injectErrorAddKey       bool
	injectErrorListKeys     bool
	injectErrorGetKey       bool
	injectErrorRemoveKey    bool
	injectErrorSign         bool
	injectErrorStr          string
	metadata                metadata.MD
}

type GRPCKeyStoreSrvr struct {
	testKeys       map[string]testKeyData
	testServerData *testServerData
	t              *testing.T
}

// Constants for server side log message formatting
const logReceivedMsgStr = "grpc key store server received %T"
const logReturningMsgStr = "grpc key store server returning %T"
const logReturningErrorMsgStr = "grpc key store server returning a test error"

//  Normally false, changing these logging options to true will
//  output information logs on the test server.  This may help when debugging
//  failing tests.
const serverLog bool = false
const verboseServerLog bool = false

// testLog wraps t.Logf making it easy to turn logging on and off
func testLog(t *testing.T, format string, a ...interface{}) {
	if serverLog {
		t.Logf(format, a...)
	}
}

// testLogVerbose wraps t.Logf making it easy to turn verbose logging on and off
func testLogVerbose(t *testing.T, format string, a ...interface{}) {
	if verboseServerLog {
		t.Logf(format, a...)
	}
}

// newGRPCKeyStoreSrvr instantiates a the GRPC keystore server for testing
func newGRPCKeyStoreSrvr(t *testing.T, testServerData *testServerData,
	testKeys map[string]testKeyData) *GRPCKeyStoreSrvr {

	st := &GRPCKeyStoreSrvr{
		testServerData: testServerData,
		testKeys:       testKeys,
		t:              t,
	}
	return st
}

func getCertsDir(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(file)
	certsDir := filepath.Join(dir, "../../fixtures/")
	return certsDir
}

func getServerTLS(t *testing.T, config *testServerConfig) *tls.Config {
	var pool *x509.CertPool
	var clientAuth = tls.NoClientCert
	var cert tls.Certificate
	var err error

	certDir := getCertsDir(t)
	if (config.tlsCertFile != "") && (config.tlsKeyFile != "") {
		cert, err = tls.LoadX509KeyPair(
			filepath.Join(certDir, config.tlsCertFile),

			filepath.Join(certDir, config.tlsKeyFile),
		)
		require.NoError(t, err)
	} else {
		// this is not a normal case -- used only to drive error testing
		// for no server TLS.
		return &tls.Config{}
	}

	// MUTUAL AUTH CASE
	if config.tlsCAFile != "" {
		clientAuth = tls.RequireAndVerifyClientCert
		pool = x509.NewCertPool()
		cacert, err := ioutil.ReadFile(filepath.Join(certDir, config.tlsCAFile))
		require.NoError(t, err)
		pool.AppendCertsFromPEM(
			cacert,
		)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   clientAuth,
	}
}

// GenerateKey processes a GenerateKey GRPC request from the client
func (st *GRPCKeyStoreSrvr) GenerateKey(ctx context.Context, msg *GenerateKeyReq) (*GenerateKeyRsp, error) {
	var t = st.t
	var tsd = st.testServerData
	var tkd testKeyData
	var err error
	var keyFound = false
	var rsp = &GenerateKeyRsp{}

	testLog(t, logReceivedMsgStr, msg)
	testLogVerbose(t, "     Gun: %s", msg.Gun)
	testLogVerbose(t, "     Role: %s", msg.Role)

	for _, tkd = range st.testKeys {
		if (msg.Role == string(tkd.keyInfo.Role)) && (msg.Gun == string(tkd.keyInfo.Gun)) {
			keyFound = true
			break
		}
	}

	if !keyFound {
		err = fmt.Errorf("unable to locate matching testkey for role:%s gun:%s", msg.Role, msg.Gun)
		return rsp, err
	}

	// if an error injection is reqeusted for testing, return it now.
	if tsd.injectErrorGenerateKey {
		testLog(t, logReturningErrorMsgStr)
		err = fmt.Errorf(tsd.injectErrorStr)
	}

	rsp = &GenerateKeyRsp{
		RemoteKeyId:        tkd.remoteKeyID,
		PublicKey:          tkd.privateKey.Public(),
		Algorithm:          string(tkd.privateKey.Algorithm()),
		SignatureAlgorithm: string(tkd.privateKey.SignatureAlgorithm()),
	}

	testLog(t, logReturningErrorMsgStr)
	testLogVerbose(t, "     RemoteKeyId: %s", rsp.RemoteKeyId)
	testLogVerbose(t, "     Algorithm: %s", rsp.Algorithm)
	testLogVerbose(t, "     SignatureAlgorithm: %s", rsp.SignatureAlgorithm)
	testLogVerbose(t, "     PublicKey: %x", rsp.PublicKey)

	return rsp, err
}

// AssocateKey processes an AssociateKey GRPC request from the client
func (st *GRPCKeyStoreSrvr) AssociateKey(ctx context.Context, msg *AssociateKeyReq) (*AssociateKeyRsp, error) {
	var t = st.t
	var tsd = st.testServerData
	var err error
	var tkd testKeyData
	var i string
	var keyFound = false
	var rsp = &AssociateKeyRsp{}

	testLog(t, logReceivedMsgStr, msg)
	testLogVerbose(t, "     KeyId: %s", msg.KeyId)
	testLogVerbose(t, "     RemoteKeyId: %s", msg.RemoteKeyId)

	for i, tkd = range st.testKeys {
		if msg.RemoteKeyId == tkd.remoteKeyID {
			keyFound = true
			break
		}
	}

	if !keyFound {
		err = fmt.Errorf("unable to locate matching testkey for remotekeyid:%s", msg.RemoteKeyId)
		return rsp, err
	}

	// if an error injection is reqeusted for testing, return it now.
	if tsd.injectErrorAssociateKey {
		testLog(t, logReturningErrorMsgStr)
		err = fmt.Errorf(tsd.injectErrorStr)
	}

	// mark the key associated (in use) and update the map
	tkd.associated = true
	st.testKeys[i] = tkd

	testLog(t, logReturningMsgStr, rsp)

	return rsp, err
}

// AddKey processes an AddKey GRPC request from the client
func (st *GRPCKeyStoreSrvr) AddKey(ctx context.Context, msg *AddKeyReq) (*AddKeyRsp, error) {
	var t = st.t
	var tsd = st.testServerData
	var tkd testKeyData
	var i string
	var err error
	var keyFound = false
	var rsp = &AddKeyRsp{}

	testLog(t, logReceivedMsgStr, msg)
	testLogVerbose(t, "     KeyID: %s", msg.KeyId)
	testLogVerbose(t, "     Gun: %s", msg.Gun)
	testLogVerbose(t, "     Role: %s", msg.Role)
	testLogVerbose(t, "     Algorithm: %s", msg.Algorithm)
	testLogVerbose(t, "     SignatureAlgorithm: %s", msg.SignatureAlgorithm)
	testLogVerbose(t, "     PublicKey: %x", msg.PublicKey)
	testLogVerbose(t, "     PrivateKey: %x", msg.PrivateKey)

	// search the test keys.  for addkey basically the only thing we are retrieving
	// is the remote key id.
	for i, tkd = range st.testKeys {
		if (msg.Role == string(tkd.keyInfo.Role)) && (msg.Gun == string(tkd.keyInfo.Gun)) {
			keyFound = true
			break
		}
	}

	if !keyFound {
		err = fmt.Errorf("unable to locate matching testkey for role:%s gun:%s", msg.Role, msg.Gun)
		return rsp, err
	}

	// if an error injection is reqeusted for testing, return it now.
	if tsd.injectErrorAddKey {
		testLog(t, logReturningErrorMsgStr)
		err = fmt.Errorf(tsd.injectErrorStr)
	}

	// mark the key associated (in use) and update the map
	tkd.associated = true
	st.testKeys[i] = tkd

	rsp = &AddKeyRsp{
		RemoteKeyId: tkd.remoteKeyID,
	}

	testLog(t, logReturningMsgStr, rsp)
	testLogVerbose(t, "     RemoteKeyId: %s", rsp.RemoteKeyId)

	return rsp, err
}

// GetKey processes an GetKey GRPC request from the client
func (st *GRPCKeyStoreSrvr) GetKey(ctx context.Context, msg *GetKeyReq) (*GetKeyRsp, error) {
	var t = st.t
	var tsd = st.testServerData
	var tkd testKeyData
	var err error
	var keyFound = false
	var rsp = &GetKeyRsp{}

	testLog(t, logReceivedMsgStr, msg)
	testLogVerbose(t, "     KeyID: %s", msg.KeyId)
	testLogVerbose(t, "     RemoteID: %s", msg.RemoteKeyId)

	for _, tkd = range st.testKeys {
		if (msg.RemoteKeyId == tkd.remoteKeyID) && (tkd.associated) {
			keyFound = true
			break
		}
	}

	if !keyFound {
		err = fmt.Errorf("unable to locate matching testkey for RemoteKeyID:%s", msg.RemoteKeyId)
		return rsp, err
	}

	// if an error injection is reqeusted for testing, return it now.
	if tsd.injectErrorGetKey {
		testLog(t, logReturningErrorMsgStr)
		err = fmt.Errorf(tsd.injectErrorStr)
	}

	rsp = &GetKeyRsp{
		Role:               string(tkd.keyInfo.Role),
		Algorithm:          string(tkd.privateKey.Algorithm()),
		SignatureAlgorithm: string(tkd.privateKey.SignatureAlgorithm()),
		PublicKey:          tkd.privateKey.Public(),
	}

	testLog(t, logReturningMsgStr, rsp)
	testLogVerbose(t, "     Role: %s", rsp.Role)
	testLogVerbose(t, "     Algorithm: %s", rsp.Algorithm)
	testLogVerbose(t, "     SignatureAlgorithm: %s", rsp.SignatureAlgorithm)
	testLogVerbose(t, "     PublicKey: %x", rsp.PublicKey)

	return rsp, err
}

// ListKeys processes a ListKeys GRPC request from the client
func (st *GRPCKeyStoreSrvr) ListKeys(ctx context.Context, msg *ListKeysReq) (*ListKeysRsp, error) {
	var t = st.t
	var tsd = st.testServerData
	var tkd testKeyData
	var err error
	var keyDataList []*ListKeysRsp_KeyInfo
	var rsp = &ListKeysRsp{}

	testLog(t, logReceivedMsgStr, msg)

	// verify the metadata made it through
	md, _ := metadata.FromContext(ctx)

	// make sure all expected metadata made it through
	// if it doesn't match, return no keys so the
	// test will fail
	for expectedKey, expectedSlice := range tsd.metadata {
		receivedSlice := md[expectedKey]
		if len(expectedSlice) != len(receivedSlice) {
			err = fmt.Errorf("number of values for expectedKey %s dont match", expectedKey)
		}
		if err == nil {
			for i := range expectedSlice {
				if expectedSlice[i] != receivedSlice[i] {
					err = fmt.Errorf("metadata does not match for expectedKey %s", expectedKey)
				}
			}
		}
	}
	if err != nil {
		testLog(t, "Expected metadata pairs not received on server")
		testLog(t, "Received metadata: %v", md)
		testLog(t, "Expected metadata: %v", tsd.metadata)
		return rsp, err
	}

	// return all the associated keys
	for _, tkd = range st.testKeys {
		if tkd.associated {
			keyData := ListKeysRsp_KeyInfo{
				KeyId:       string(tkd.privateKey.ID()),
				RemoteKeyId: tkd.remoteKeyID,
				Gun:         string(tkd.keyInfo.Gun),
				Role:        string(tkd.keyInfo.Role),
			}
			keyDataList = append(keyDataList, &keyData)
		}
	}

	// if an error injection is reqeusted for testing, return it now.
	if tsd.injectErrorListKeys {
		testLog(t, logReturningErrorMsgStr)
		err = fmt.Errorf(tsd.injectErrorStr)
	}

	rsp = &ListKeysRsp{
		KeyData: keyDataList,
	}

	testLog(t, logReturningMsgStr, rsp)

	for i, key := range rsp.KeyData {
		testLogVerbose(t, "     Key %d", i)
		testLogVerbose(t, "        KeyId: %s", key.KeyId)
		testLogVerbose(t, "RemoteKeyId: %s", key.RemoteKeyId)
		testLogVerbose(t, "        Gun: %s", key.Gun)
		testLogVerbose(t, "        Role: %s", key.Role)
	}

	return rsp, err
}

// RemoveKey processes the RemoveKey GRPC request from the client
func (st *GRPCKeyStoreSrvr) RemoveKey(ctx context.Context, msg *RemoveKeyReq) (*RemoveKeyRsp, error) {
	var t = st.t
	var tsd = st.testServerData
	var tkd testKeyData
	var i string
	var err error
	var keyFound = false
	var rsp = &RemoveKeyRsp{}

	testLog(t, logReceivedMsgStr, msg)
	testLogVerbose(t, "     KeyID: %s", msg.KeyId)
	testLogVerbose(t, "     RemoteID: %s", msg.RemoteKeyId)

	for i, tkd = range st.testKeys {
		if (msg.RemoteKeyId == tkd.remoteKeyID) && (tkd.associated) {
			keyFound = true
			tkd.associated = false
			// update the map as Associated
			st.testKeys[i] = tkd
			break
		}
	}

	if !keyFound {
		err = fmt.Errorf("unable to locate matching testkey for RemoteKeyID:%s", msg.RemoteKeyId)
		return rsp, err
	}

	// if an error injection is reqeusted for testing, return it now.
	if tsd.injectErrorRemoveKey {
		testLog(t, logReturningErrorMsgStr)
		err = fmt.Errorf(tsd.injectErrorStr)
	}

	testLog(t, logReturningMsgStr, rsp)

	return rsp, err
}

// Sign processes the Sign GRPC request from the client
func (st *GRPCKeyStoreSrvr) Sign(ctx context.Context, msg *SignReq) (*SignRsp, error) {
	var t = st.t
	var tsd = st.testServerData
	var err error
	var tkd testKeyData
	var keyFound = false
	var rsp = &SignRsp{}

	testLog(t, logReceivedMsgStr, msg)
	testLogVerbose(t, "     KeyID: %s", msg.KeyId)
	testLogVerbose(t, "     RemoteID: %s", msg.RemoteKeyId)
	testLogVerbose(t, "     HashAlgorithm: %s", msg.HashAlgorithm)
	testLogVerbose(t, "     Message: %x", msg.Message)

	for _, tkd = range st.testKeys {
		if msg.RemoteKeyId == tkd.remoteKeyID {
			keyFound = true
			break
		}
	}

	if !keyFound {
		err = fmt.Errorf("unable to locate matching testkey for remoteID:%s", tkd.remoteKeyID)
		return rsp, err
	}

	// Sign the message.  Note!!! The GRPC server side is responsible for all hashing
	// and padding before signing!  In this test, Sign() does that
	// for us.
	signature, err := tkd.privateKey.Sign(rand.Reader, msg.Message, nil)

	// if an error injection is reqeusted for testing, return it now.
	if tsd.injectErrorSign {
		testLog(t, logReturningErrorMsgStr)
		err = fmt.Errorf(tsd.injectErrorStr)
	}

	rsp = &SignRsp{
		Signature: signature,
	}

	testLog(t, logReturningMsgStr, rsp)
	testLogVerbose(t, "     Signature: %x", rsp.Signature)

	return rsp, err
}

//
//  Here are the Tests!
//

// Actual tests for utilizing GRPC client
// TestGenerateKey is a full test of GPRC keystore operations
// using GenerateKey to populate the keys
func TestGenerateKey(t *testing.T) {
	var tkd testKeyData
	var err error
	testKeys := make(map[string]testKeyData)

	// setup three ECDSA keys for this test
	err = setupTestKey(t, &testKeys, "testrootkey", data.ECDSAKey,
		data.CanonicalRootRole, "", false)
	require.NoError(t, err)
	err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun1", false)
	require.NoError(t, err)
	err = setupTestKey(t, &testKeys, "testtargetkeygun2", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun2", false)
	require.NoError(t, err)

	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)

	// test the location
	loc := c.Location()
	require.Equal(t, "Remote GRPC Key Store @ "+clientConfig.Server, loc)

	// test the name
	name := c.Name()
	require.Equal(t, "GRPC remote store", name)

	//
	// ListKeys Test: Verify no keys
	//
	km := c.ListKeys()
	// verify zero keys returned
	require.Equal(t, 0, len(km))

	// GenerateKey Test for root key
	tkd = testKeys["testrootkey"]
	pk, err := c.GenerateKey(tkd.keyInfo)
	require.NoError(t, err)
	// chect that all response fields from the GRPC server match
	require.Equal(t, pk.Public(), tkd.privateKey.Public())
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	// check that the generated key was stored locally in the key list
	k := c.keys[pk.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// GenerateKey for gun 1
	tkd = testKeys["testtargetkeygun1"]
	pk, err = c.GenerateKey(tkd.keyInfo)
	require.NoError(t, err)
	// chect that all response fields from the GRPC server match
	require.Equal(t, pk.Public(), tkd.privateKey.Public())
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	// check that the generated key was stored locally in the key list
	k = c.keys[pk.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// GenerateKey for gun 2
	tkd = testKeys["testtargetkeygun2"]
	pk, err = c.GenerateKey(tkd.keyInfo)
	require.NoError(t, err)
	// check that all response fields from the GRPC server match
	require.Equal(t, pk.Public(), tkd.privateKey.Public())
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	// check that the generated key was stored locally in the key list
	k = c.keys[pk.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// ListKeys - verifiy all three keys listed
	km = c.ListKeys()
	require.Equal(t, 3, len(km))
	// walk through the test keys, make sure they are all correct
	for i := range testKeys {
		tkd = testKeys[i]
		require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
	}

	// Test GetKeyInfo for the test root key (should succeed)
	var ki trustmanager.KeyInfo
	tkd = testKeys["testrootkey"]
	ki, err = c.GetKeyInfo(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, tkd.keyInfo, ki)

	// GetKey for all three keys
	var role data.RoleName
	tkd = testKeys["testrootkey"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	tkd = testKeys["testtargetkeygun1"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	tkd = testKeys["testtargetkeygun2"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	// Test getting the crypto.Singer
	//gs := pk.CrytoSigner()

	// Test GRPCkeySigner.Public()
	//publicKey, err := gs.Public()
	//require.NoError(t, err)
	//parsedPublicKey, err := x509.ParsePKIXPublicKey(pk.Public())
	//require.Equal(t, publicKey, parsedPublicKey)

	// Test GRPCPrivateKey.Private()... should return nil
	privateKey := pk.Private()
	require.Empty(t, privateKey)

	// Test a Signing Operation...
	msg := []byte("Sign this data")
	_, err = pk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// RemoveKey  for all three keys
	tkd = testKeys["testrootkey"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun1"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun2"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	// ListKeys and Verify all keys deleted
	km = c.ListKeys()
	// verify zero keys returned
	require.Equal(t, 0, len(km))

	// close the client GRPC connection
	c.closeClient()
}

// TestAddKey is a full test of GPRC keystore operations
// using AddKey to populate the keys
func TestAddKey(t *testing.T) {
	var tkd testKeyData
	var err error
	testKeys := make(map[string]testKeyData)

	// setup three ECDSA keys for this test
	err = setupTestKey(t, &testKeys, "testrootkey", data.ECDSAKey,
		data.CanonicalRootRole, "", false)
	require.NoError(t, err)
	err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun1", false)
	require.NoError(t, err)
	err = setupTestKey(t, &testKeys, "testtargetkeygun2", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun2", false)
	require.NoError(t, err)

	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)

	//
	// ListKeys Test: Verify no keys
	//
	km := c.ListKeys()
	// verify zero keys returned
	require.Equal(t, 0, len(km))

	// AddKey Test for root key
	tkd = testKeys["testrootkey"]
	err = c.AddKey(tkd.keyInfo, tkd.privateKey)
	require.NoError(t, err)

	// check that the added key was stored locally in the key list
	k := c.keys[tkd.privateKey.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// AddKey for gun 1
	tkd = testKeys["testtargetkeygun1"]
	err = c.AddKey(tkd.keyInfo, tkd.privateKey)
	require.NoError(t, err)

	// check that the added key was stored locally in the key list
	k = c.keys[tkd.privateKey.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// AddKey for gun 2
	tkd = testKeys["testtargetkeygun2"]
	err = c.AddKey(tkd.keyInfo, tkd.privateKey)
	require.NoError(t, err)
	// check that the generated key was stored locally in the key list
	k = c.keys[tkd.privateKey.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// ListKeys - verifiy all three keys listed
	km = c.ListKeys()
	require.Equal(t, 3, len(km))
	// walk through the test keys, make sure they are all correct
	for i := range testKeys {
		tkd = testKeys[i]
		require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
	}

	// GetKey for all three keys
	var role data.RoleName
	tkd = testKeys["testrootkey"]
	pk, role, err := c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	tkd = testKeys["testtargetkeygun1"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	tkd = testKeys["testtargetkeygun2"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	// Test a Signing Operation...
	// The Sign operation does verification so we know the signature is good
	msg := []byte("Sign this data")
	_, err = pk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// RemoveKey  for all three keys
	tkd = testKeys["testrootkey"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun1"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun2"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	// ListKeys and Verify all keys deleted
	km = c.ListKeys()
	// verify zero keys returned
	require.Equal(t, 0, len(km))

	// close the client GRPC connection
	c.closeClient()
}

// TestKeysAlreadyInStore is a full test of GPRC keystore operations
// where the keys are already in the keystore.
func TestKeysAlreadyInStore(t *testing.T) {
	var tkd testKeyData
	var err error
	testKeys := make(map[string]testKeyData)

	// setup three _pre-enabled_ ECDSA keys for this test
	err = setupTestKey(t, &testKeys, "testrootkey", data.ECDSAKey,
		data.CanonicalRootRole, "", true)
	require.NoError(t, err)
	err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun1", true)
	require.NoError(t, err)
	err = setupTestKey(t, &testKeys, "testtargetkeygun2", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun2", true)
	require.NoError(t, err)

	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)

	// ListKeys - verifiy all three keys listed
	km := c.ListKeys()
	require.Equal(t, 3, len(km))
	// walk through the test keys, make sure they are all correct
	for i := range testKeys {
		tkd = testKeys[i]
		require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
	}

	// GetKey for all three keys
	var role data.RoleName
	tkd = testKeys["testrootkey"]
	pk, role, err := c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	tkd = testKeys["testtargetkeygun1"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	tkd = testKeys["testtargetkeygun2"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	// Test a Signing Operation...
	// The Sign operation does verification so we know the signature is good
	msg := []byte("Sign this data")
	_, err = pk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// RemoveKey  for all three keys
	tkd = testKeys["testrootkey"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun1"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun2"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	// ListKeys and Verify all keys deleted
	km = c.ListKeys()
	// verify zero keys returned
	require.Equal(t, 0, len(km))

	// close the client GRPC connection
	c.closeClient()
}

// Test two different key types -- RSA & ECDSA.  ED25519 keys are not yet supported,
// but should work fine once the the golang packages that support
// ParsePublicKey() are updated with ED25519 support
func TestKeyTypes(t *testing.T) {
	var tkd testKeyData
	var err error
	testKeys := make(map[string]testKeyData)

	// setup two keys for this test
	// use a RSA Key for the root key, and ecdsa for target
	err = setupTestKey(t, &testKeys, "testrootkey", data.RSAKey,
		data.CanonicalRootRole, "", false)
	require.NoError(t, err)
	// use an ecdsa Key for gun 1
	err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun1", false)
	require.NoError(t, err)

	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)

	// test the location
	// loc := c.Location()
	// require.Equal(t, "Remote GRPC KeyStore @ "+addr, loc)

	// test the name
	name := c.Name()
	require.Equal(t, "GRPC remote store", name)

	//
	// ListKeys Test: Verify no keys
	//
	km := c.ListKeys()
	// verify zero keys returned
	require.Equal(t, 0, len(km))

	// GenerateKey Test for root key
	tkd = testKeys["testrootkey"]
	pk, err := c.GenerateKey(tkd.keyInfo)
	require.NoError(t, err)
	// chect that all response fields from the GRPC server match
	require.Equal(t, pk.Public(), tkd.privateKey.Public())
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	// check that the generated key was stored locally in the key list
	k := c.keys[pk.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// GenerateKey for gun 1
	tkd = testKeys["testtargetkeygun1"]
	pk, err = c.GenerateKey(tkd.keyInfo)
	require.NoError(t, err)
	// chect that all response fields from the GRPC server match
	require.Equal(t, pk.Public(), tkd.privateKey.Public())
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	// check that the generated key was stored locally in the key list
	k = c.keys[pk.ID()]
	require.Equal(t, k.gun, tkd.keyInfo.Gun)
	require.Equal(t, k.role, tkd.keyInfo.Role)
	require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
	require.NoError(t, err)

	// ListKeys - verifiy all new keys are listed
	km = c.ListKeys()
	require.Equal(t, 2, len(km))
	// walk through the test keys, make sure they are all correct
	for i := range testKeys {
		tkd = testKeys[i]
		require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
	}

	// GetKey and sign for each key
	var role data.RoleName
	tkd = testKeys["testrootkey"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	// Test a Signing Operation with the RSA key type
	msg := []byte("Sign this with RSA Key")
	_, err = pk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun1"]
	pk, role, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)
	require.Equal(t, role, tkd.keyInfo.Role)
	require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
	require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
	require.Equal(t, pk.Public(), tkd.privateKey.Public())

	// Test a Signing Operation with the ECDSA key type
	msg = []byte("Sign this with the ECDSA Key")
	_, err = pk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	// RemoveKey for all three keys
	tkd = testKeys["testrootkey"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	tkd = testKeys["testtargetkeygun1"]
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.NoError(t, err)

	// ListKeys and Verify all keys deleted
	km = c.ListKeys()
	// verify zero keys returned
	require.Equal(t, 0, len(km))

	// close the client GRPC connection
	c.closeClient()
}

// TestConfigErrors
// Test TLS - Client CA cert doesn't match server.  An error is expected in this
// case since the client ca_cert doesn't match the server
// Client configures ca
// Server configures cert, key
//
func TestConfigErrors(t *testing.T) {
	var err error
	testKeys := make(map[string]testKeyData)

	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, false, false)

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// Test with no CA file configured on client case
	_, err = NewGRPCKeyStore(clientConfig)
	// we expect an config error: no TLS CA file configured
	require.Error(t, err)

	// Test with CA file on client and client cert but no client key
	clientConfig.TLSCAFile = filepath.Join(getCertsDir(t), "root-ca.crt")
	clientConfig.TLSCertFile = filepath.Join(getCertsDir(t), "notary-escrow.crt")
	_, err = NewGRPCKeyStore(clientConfig)
	// we expect an config error: coding client cert requires coding client key
	require.Error(t, err)

	// Test with CA file on client and client key but no client cert
	clientConfig.TLSCertFile = ""
	clientConfig.TLSKeyFile = filepath.Join(getCertsDir(t), "notary-escrow.key")
	_, err = NewGRPCKeyStore(clientConfig)
	// we expect an config error: coding client key requires coding client cert
	require.Error(t, err)

	// Test with non-existent cert file
	clientConfig.TLSCertFile = filepath.Join(getCertsDir(t), "noexistantfile.crt")
	clientConfig.TLSKeyFile = filepath.Join(getCertsDir(t), "notary-escrow.key")
	_, err = NewGRPCKeyStore(clientConfig)
	// we expect an config error: cert file must be valid
	require.Error(t, err)

	// Test with non-existent cert file
	clientConfig.TLSCertFile = filepath.Join(getCertsDir(t), "notary-escrow.crt")
	clientConfig.TLSKeyFile = filepath.Join(getCertsDir(t), "noexistantfile.key")
	_, err = NewGRPCKeyStore(clientConfig)
	// we expect an config error: key file must be valid
	require.Error(t, err)
}

// Test TLS - Server Auth
// Client configures root ca
// Server configures cert, key
func TestTLSServerAuth(t *testing.T) {
	var err error
	testKeys := make(map[string]testKeyData)

	// setting verifyServerCert to true and mutualAuth to false
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)

	// close the client GRPC connection
	c.closeClient()
}

// Test TLS - mutual authentication (also called client authentication)
// Client configures cert, key, and ca cert files
// Server configures cert, key, and ca cert files
// As a simplification, the same keys/certs are used in
// both directions to avoid having to make new keys/certs
func TestTLSMutualAuth(t *testing.T) {
	var err error
	testKeys := make(map[string]testKeyData)

	// setting mutualAuth to true is the key difference for this test
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, true)

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)

	// close the client GRPC connection
	c.closeClient()
}

// Test TLS - Client CA cert doesn't match server.  An error is expected in this
// case since the client ca_cert doesn't match the server
// Client configures ca
// Server configures cert, key
//
func TestTLSServerVerificationFailure(t *testing.T) {
	var err error
	testKeys := make(map[string]testKeyData)

	// setting client ca file that doesn't match the server config
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, false, false)
	clientConfig.TLSCAFile = filepath.Join(getCertsDir(t), "secure.example.com.crt")
	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	_, err = NewGRPCKeyStore(clientConfig)

	// we expect an error from TLS here...client cert doesn't match server
	require.Error(t, err)
}

// Test TLS - configured Client CA file doesn't exist
// case since the client ca_cert doesn't match the server
// Client configures ca
// Server configures cert, key
//
func TestTLSClientCAFileNotFound(t *testing.T) {
	var err error
	testKeys := make(map[string]testKeyData)

	// setting client ca file that doesn't match the server config
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, false, false)
	clientConfig.TLSCAFile = filepath.Join(getCertsDir(t), "noexistantfile.crt")
	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client for testing
	_, err = NewGRPCKeyStore(clientConfig)

	// we expect an error from TLS here...client CA file not found
	require.Error(t, err)
}

// Test TLS - no TLS on server case.  An error is expected in this case since
// the client does not allow the server to not have TLS configured.
// Client configures ca cert
// Server configures nothing
func TestTLSNoServerTLSConfiguredError(t *testing.T) {
	var err error
	testKeys := make(map[string]testKeyData)

	// start with minimum permissible config
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// then reset the server config to nothing...
	serverConfig.tlsKeyFile = ""
	serverConfig.tlsCertFile = ""

	// start the GRPC test server
	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client, expecting client startup to fail
	_, err = NewGRPCKeyStore(clientConfig)
	// we expect an error from TLS here...client doesn't allow an insecure server
	require.Error(t, err)
}

// TestErrors
// Test Various Error Cases
// Server will inject an error into all grpc responses
func TestErrors(t *testing.T) {
	var tkd testKeyData
	var err error
	testKeys := make(map[string]testKeyData)

	// use an ecdsa Key for error testing
	err = setupTestKey(t, &testKeys, "testerrorkey", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun1", true)
	require.NoError(t, err)
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server with all errors turned on place
	testServerData.injectErrorGenerateKey = true
	testServerData.injectErrorAssociateKey = true
	testServerData.injectErrorAddKey = true
	testServerData.injectErrorListKeys = true
	testServerData.injectErrorGetKey = true
	testServerData.injectErrorRemoveKey = true
	testServerData.injectErrorSign = true

	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)
	tkd = testKeys["testerrorkey"]

	// Test GetKeyInfo for a bogus key (should fail)
	_, err = c.GetKeyInfo("bogus")
	require.Error(t, err)

	// GenerateKey Error Test
	pk, err := c.GenerateKey(tkd.keyInfo)
	require.Equal(t, nil, pk)
	require.Error(t, err)

	// AddKey Error Test
	err = c.AddKey(tkd.keyInfo, tkd.privateKey)
	require.Error(t, err)

	// GetKey Error Test
	pk, _, err = c.GetKey(tkd.privateKey.ID())
	require.Error(t, err)
	require.Equal(t, nil, pk)

	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.Error(t, err)

	// close the client GRPC connection
	c.closeClient()
}

// TestSubsequentErrors
// Test Various Error Cases
// In this case we let the Server get things started without errors so we
// can get a bet farther, but then generate grpc error responses that we
// couldn't get to above.
func TestSubsequentErrors(t *testing.T) {
	var tkd testKeyData
	var err error
	testKeys := make(map[string]testKeyData)

	// use an ecdsa Key for error testing
	err = setupTestKey(t, &testKeys, "testerrorkey", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun1", true)
	require.NoError(t, err)
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server with all errors turned on place
	testServerData.injectErrorAssociateKey = true
	testServerData.injectErrorRemoveKey = true
	testServerData.injectErrorSign = true

	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	// start the client
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)
	tkd = testKeys["testerrorkey"]

	// GenerateKey Error Test should still fail on the associate failure
	pk, err := c.GenerateKey(tkd.keyInfo)
	require.Equal(t, nil, pk)
	require.Error(t, err)

	// Add key should succeed (we want to get one key in there)
	err = c.AddKey(tkd.keyInfo, tkd.privateKey)
	require.NoError(t, err)

	// GetKey Should succeed
	pk, _, err = c.GetKey(tkd.privateKey.ID())
	require.NoError(t, err)

	// Test a Signing Operation with the ECDSA key type
	msg := []byte("Sign this with the ECDSA Key")
	_, err = pk.Sign(rand.Reader, msg, nil)
	require.Error(t, err)

	// Remove Key should fail
	err = c.RemoveKey(string(tkd.privateKey.ID()))
	require.Error(t, err)
}

// TestMetadata
// Non-empty metadata is sent from client to server
func TestMetadata(t *testing.T) {
	var err error
	testKeys := make(map[string]testKeyData)

	// use an ecdsa Key for error testing
	err = setupTestKey(t, &testKeys, "testkey", data.ECDSAKey,
		data.CanonicalTargetsRole, "myreg.com/myorg/gun1", true)
	require.NoError(t, err)
	serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

	// start the GRPC test server
	testServerData.metadata = metadata.Pairs(testMetadataKey, testMetadataValue)

	closer := setupTestServer(t, serverConfig, testServerData, testKeys)
	defer closer()

	clientConfig.Metadata = metadata.Pairs(testMetadataKey, testMetadataValue)

	// start the client
	c, err := NewGRPCKeyStore(clientConfig)
	require.NoError(t, err)

	// ListKeys verifies the metadata - if we see a key returned it means
	// the metadata matches
	km := c.ListKeys()
	require.Equal(t, 1, len(km))

	// close the client GRPC connection
	c.closeClient()
}
