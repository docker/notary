package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"crypto/subtle"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/docker/pkg/term"
	notaryclient "github.com/docker/notary/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cmdTufList = &cobra.Command{
	Use:   "list [ GUN ]",
	Short: "Lists targets for a trusted collection.",
	Long:  "Lists all targets for a trusted collection identified by the Globally Unique Name.",
	Run:   tufList,
}

var cmdTufAdd = &cobra.Command{
	Use:   "add [ GUN ] <target> <file>",
	Short: "adds the file as a target to the trusted collection.",
	Long:  "adds the file as a target to the local trusted collection identified by the Globally Unique Name.",
	Run:   tufAdd,
}

var cmdTufRemove = &cobra.Command{
	Use:   "remove [ GUN ] <target>",
	Short: "Removes a target from a trusted collection.",
	Long:  "removes a target from the local trusted collection identified by the Globally Unique Name.",
	Run:   tufRemove,
}

var cmdTufInit = &cobra.Command{
	Use:   "init [ GUN ]",
	Short: "initializes a local trusted collection.",
	Long:  "initializes a local trusted collection identified by the Globally Unique Name.",
	Run:   tufInit,
}

var cmdTufLookup = &cobra.Command{
	Use:   "lookup [ GUN ] <target>",
	Short: "Looks up a specific target in a trusted collection.",
	Long:  "looks up a specific target in a trusted collection identified by the Globally Unique Name.",
	Run:   tufLookup,
}

var cmdTufPublish = &cobra.Command{
	Use:   "publish [ GUN ]",
	Short: "publishes the local trusted collection.",
	Long:  "publishes the local trusted collection identified by the Globally Unique Name, sending the local changes to a remote trusted server.",
	Run:   tufPublish,
}

var cmdVerify = &cobra.Command{
	Use:   "verify [ GUN ] <target>",
	Short: "verifies if the content is included in the trusted collection",
	Long:  "verifies if the data passed in STDIN is included in the trusted collection identified by the Global Unique Name.",
	Run:   verify,
}

func tufAdd(cmd *cobra.Command, args []string) {
	if len(args) < 3 {
		cmd.Usage()
		fatalf("must specify a GUN, target, and path to target data")
	}

	gun := args[0]
	targetName := args[1]
	targetPath := args[2]

	parseConfig()

	nRepo, err := notaryclient.NewNotaryRepository(trustDir, gun, remoteTrustServer, getTransport(gun, true), retriever)
	if err != nil {
		fatalf(err.Error())
	}

	target, err := notaryclient.NewTarget(targetName, targetPath)
	if err != nil {
		fatalf(err.Error())
	}
	err = nRepo.AddTarget(target)
	if err != nil {
		fatalf(err.Error())
	}
	fmt.Printf("Addition of %s to %s staged for next publish.\n", targetName, gun)
}

func tufInit(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("Must specify a GUN")
	}

	gun := args[0]
	parseConfig()

	nRepo, err := notaryclient.NewNotaryRepository(trustDir, gun, remoteTrustServer, getTransport(gun, false), retriever)
	if err != nil {
		fatalf(err.Error())
	}

	keysMap := nRepo.KeyStoreManager.RootKeyStore().ListKeys()

	var rootKeyID string
	if len(keysMap) < 1 {
		fmt.Println("No root keys found. Generating a new root key...")
		rootKeyID, err = nRepo.KeyStoreManager.GenRootKey("ECDSA")
		if err != nil {
			fatalf(err.Error())
		}
	} else {
		// TODO(diogo): ask which root key to use
		for keyID := range keysMap {
			rootKeyID = keyID
		}

		fmt.Printf("Root key found, using: %s\n", rootKeyID)
	}

	rootCryptoService, err := nRepo.KeyStoreManager.GetRootCryptoService(rootKeyID)
	if err != nil {
		fatalf(err.Error())
	}

	err = nRepo.Initialize(rootCryptoService)
	if err != nil {
		fatalf(err.Error())
	}
}

func tufList(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("must specify a GUN")
	}
	gun := args[0]
	parseConfig()

	nRepo, err := notaryclient.NewNotaryRepository(trustDir, gun, remoteTrustServer, getTransport(gun, true), retriever)
	if err != nil {
		fatalf(err.Error())
	}

	// Retreive the remote list of signed targets
	targetList, err := nRepo.ListTargets()
	if err != nil {
		fatalf(err.Error())
	}

	// Print all the available targets
	for _, t := range targetList {
		fmt.Printf("%s %x %d\n", t.Name, t.Hashes["sha256"], t.Length)
	}
}

func tufLookup(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		cmd.Usage()
		fatalf("must specify a GUN and target")
	}
	gun := args[0]
	targetName := args[1]
	parseConfig()

	nRepo, err := notaryclient.NewNotaryRepository(trustDir, gun, remoteTrustServer, getTransport(gun, true), retriever)
	if err != nil {
		fatalf(err.Error())
	}

	target, err := nRepo.GetTargetByName(targetName)
	if err != nil {
		fatalf(err.Error())
	}

	fmt.Println(target.Name, fmt.Sprintf("sha256:%x", target.Hashes["sha256"]), target.Length)
}

func tufPublish(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("Must specify a GUN")
	}

	gun := args[0]
	parseConfig()

	fmt.Println("Pushing changes to ", gun, ".")

	nRepo, err := notaryclient.NewNotaryRepository(trustDir, gun, remoteTrustServer, getTransport(gun, false), retriever)
	if err != nil {
		fatalf(err.Error())
	}

	err = nRepo.Publish()
	if err != nil {
		fatalf(err.Error())
	}
}

func tufRemove(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		cmd.Usage()
		fatalf("must specify a GUN and target")
	}
	gun := args[0]
	targetName := args[1]
	parseConfig()

	repo, err := notaryclient.NewNotaryRepository(trustDir, gun, remoteTrustServer,
		getTransport(gun, false), retriever)
	if err != nil {
		fatalf(err.Error())
	}
	err = repo.RemoveTarget(targetName)
	if err != nil {
		fatalf(err.Error())
	}

	fmt.Printf("Removal of %s from %s staged for next publish.\n", targetName, gun)
}

func verify(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		cmd.Usage()
		fatalf("must specify a GUN and target")
	}
	parseConfig()

	// Reads all of the data on STDIN
	payload, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fatalf("error reading content from STDIN: %v", err)
	}

	gun := args[0]
	targetName := args[1]
	nRepo, err := notaryclient.NewNotaryRepository(trustDir, gun, remoteTrustServer, getTransport(gun, true), retriever)
	if err != nil {
		fatalf(err.Error())
	}

	target, err := nRepo.GetTargetByName(targetName)
	if err != nil {
		logrus.Error("notary: data not present in the trusted collection.")
		os.Exit(-11)
	}

	// Create hasher and hash data
	stdinHash := sha256.Sum256(payload)
	serverHash := target.Hashes["sha256"]

	if subtle.ConstantTimeCompare(stdinHash[:], serverHash) == 0 {
		logrus.Error("notary: data not present in the trusted collection.")
		os.Exit(1)
	} else {
		_, _ = os.Stdout.Write(payload)
	}
	return
}

type passwordStore struct {
	anonymous bool
}

func (ps passwordStore) Basic(u *url.URL) (string, string) {
	if ps.anonymous {
		return "", ""
	}

	stdin := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stdout, "Enter username: ")

	userIn, err := stdin.ReadBytes('\n')
	if err != nil {
		logrus.Errorf("error processing username input: %s", err)
		return "", ""
	}

	username := strings.TrimSpace(string(userIn))

	state, err := term.SaveState(0)
	if err != nil {
		logrus.Errorf("error saving terminal state, cannot retrieve password: %s", err)
		return "", ""
	}
	term.DisableEcho(0, state)
	defer term.RestoreTerminal(0, state)

	fmt.Fprintf(os.Stdout, "Enter password: ")

	userIn, err = stdin.ReadBytes('\n')
	fmt.Fprintln(os.Stdout)
	if err != nil {
		logrus.Errorf("error processing password input: %s", err)
		return "", ""
	}
	password := strings.TrimSpace(string(userIn))

	return username, password
}

func getTransport(gun string, readOnly bool) http.RoundTripper {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: viper.GetBool("skipTLSVerify"),
	}

	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   true,
	}

	// TODO(dmcgowan): add notary specific headers
	authTransport := transport.NewTransport(base)
	pingClient := &http.Client{
		Transport: authTransport,
		Timeout:   5 * time.Second,
	}
	endpointStr := "https://notary.docker.io/v2/"
	req, err := http.NewRequest("GET", endpointStr, nil)
	if err != nil {
		fatalf(err.Error())
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		fatalf(err.Error())
	}
	defer resp.Body.Close()

	challengeManager := auth.NewSimpleChallengeManager()
	if err := challengeManager.AddResponse(resp); err != nil {
		fatalf(err.Error())
	}

	ps := passwordStore{anonymous: readOnly}
	tokenHandler := auth.NewTokenHandler(authTransport, ps, gun, "push", "pull")
	basicHandler := auth.NewBasicHandler(ps)
	modifier := transport.RequestModifier(auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler))
	return transport.NewTransport(base, modifier)
}
