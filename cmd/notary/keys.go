package main

import (
	"crypto/x509"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/notary/trustmanager"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var subjectKeyID string

var cmdKeys = &cobra.Command{
	Use:   "keys",
	Short: "Operates on keys.",
	Long:  "operations on signature keys and trusted certificate authorities.",
	Run:   keysList,
}

func init() {
	cmdKeys.AddCommand(cmdKeysTrust)
	cmdKeys.AddCommand(cmdKeysRemove)
	cmdKeys.AddCommand(cmdKeysGenerate)
}

var cmdKeysRemove = &cobra.Command{
	Use:   "remove [ Subject Key ID ]",
	Short: "Removes trust from a specific certificate authority or certificate.",
	Long:  "remove trust from a specific certificate authority.",
	Run:   keysRemove,
}

var cmdKeysTrust = &cobra.Command{
	Use:   "trust [ certificate ]",
	Short: "Trusts a new certificate.",
	Long:  "adds a the certificate to the trusted certificate authority list.",
	Run:   keysTrust,
}

var cmdKeysGenerate = &cobra.Command{
	Use:   "generate [ GUN ]",
	Short: "Generates a new key for a specific GUN.",
	Long:  "generates a new key for a specific Global Unique Name.",
	Run:   keysGenerate,
}

// keysRemove deletes Certificates based on hash and Private Keys
// based on GUNs.
func keysRemove(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("must specify a SHA256 SubjectKeyID of the certificate")
	}

	//TODO (diogo): Validate Global Unique Name. We probably want to reject 1 char GUNs.
	gunOrID := args[0]

	// Try to retrieve the ID from the CA store.
	cert, err := caStore.GetCertificateByFingerprint(gunOrID)
	if err == nil {
		fmt.Printf("Removing: ")
		printCert(cert)

		// If the ID is found, remove it.
		err = caStore.RemoveCert(cert)
		if err != nil {
			fatalf("failed to remove certificate from KeyStore")
		}
		return
	}

	// Try to retrieve the ID from the Certificate store.
	cert, err = certificateStore.GetCertificateByFingerprint(gunOrID)
	if err == nil {
		fmt.Printf("Removing: ")
		printCert(cert)

		// If the ID is found, remove it.
		err = certificateStore.RemoveCert(cert)
		if err != nil {
			fatalf("failed to remove certificate from KeyStore")
		}
		return
	}

	// We didn't find a certificate with this ID, let's try to see if we can find keys.
	keyList := privKeyStore.ListDir(gunOrID)
	if len(keyList) < 1 {
		fatalf("no Private Keys found under Global Unique Name: %s", gunOrID)
	}

	// List all the keys about to be removed
	fmt.Println("Are you sure you want to remove the following keys? (yes/no)", gunOrID)
	for _, k := range keyList {
		printKey(k)
	}

	// Ask for confirmation before removing keys
	confirmed := askConfirm()
	if !confirmed {
		fatalf("aborting action.")
	}

	// Remove all the keys under the Global Unique Name
	err = privKeyStore.RemoveDir(gunOrID)
	if err != nil {
		fatalf("failed to remove all Private keys under Global Unique Name: %s", gunOrID)
	}
	fmt.Printf("Removing all Private keys from: %s \n", gunOrID)
}

//TODO (diogo): Ask the use if she wants to trust the GUN in the cert
func keysTrust(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("please provide a URL or filename to a certificate")
	}

	certLocationStr := args[0]
	var cert *x509.Certificate

	// Verify if argument is a valid URL
	url, err := url.Parse(certLocationStr)
	if err == nil && url.Scheme != "" {
		cert, err = trustmanager.GetCertFromURL(certLocationStr)
		if err != nil {
			fatalf("error retrieving certificate from url (%s): %v", certLocationStr, err)
		}
	} else if _, err := os.Stat(certLocationStr); err == nil {
		// Try to load the certificate from the file
		cert, err = trustmanager.LoadCertFromFile(certLocationStr)
		if err != nil {
			fatalf("error adding certificate from file: %v", err)
		}
	} else {
		fatalf("please provide a file location or URL for CA certificate.")
	}

	// Ask for confirmation before adding certificate into repository
	fmt.Printf("Are you sure you want to add trust for: %s? (yes/no)\n", cert.Subject.CommonName)
	confirmed := askConfirm()
	if !confirmed {
		fatalf("aborting action.")
	}

	err = nil
	if cert.IsCA {
		err = caStore.AddCert(cert)
	} else {
		err = certificateStore.AddCert(cert)
	}
	if err != nil {
		fatalf("error adding certificate from file: %v", err)
	}

	fmt.Printf("Adding: ")
	printCert(cert)

}

func keysList(cmd *cobra.Command, args []string) {
	if len(args) > 0 {
		cmd.Usage()
		os.Exit(1)
	}

	fmt.Println("# Trusted CAs:")
	trustedCAs := caStore.GetCertificates()
	for _, c := range trustedCAs {
		printCert(c)
	}

	fmt.Println("")
	fmt.Println("# Trusted Certificates:")
	trustedCerts := certificateStore.GetCertificates()
	for _, c := range trustedCerts {
		printCert(c)
	}

	fmt.Println("")
	fmt.Println("# Signing keys: ")
	for _, k := range privKeyStore.ListAll() {
		printKey(k)
	}
}

func keysGenerate(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("must specify a GUN")
	}

	//TODO (diogo): Validate GUNs. Don't allow '/' or '\' for now.
	gun := args[0]
	if gun[0:1] == "/" || gun[0:1] == "\\" {
		fatalf("invalid Global Unique Name: %s", gun)
	}

	// _, cert, err := generateKeyAndCert(gun)
	// if err != nil {
	// 	fatalf("could not generate key: %v", err)
	// }

	// certificateStore.AddCert(cert)
	// fingerprint := trustmanager.FingerprintCert(cert)
	// fmt.Println("Generated new keypair with ID: ", fingerprint)
}

func printCert(cert *x509.Certificate) {
	timeDifference := cert.NotAfter.Sub(time.Now())
	fingerprint := trustmanager.FingerprintCert(cert)
	fmt.Printf("%s %s (expires in: %v days)\n", cert.Subject.CommonName, fingerprint, math.Floor(timeDifference.Hours()/24))
}

func printKey(keyPath string) {
	keyPath = strings.TrimSuffix(keyPath, filepath.Ext(keyPath))
	keyPath = strings.TrimPrefix(keyPath, viper.GetString("privDir"))

	fingerprint := filepath.Base(keyPath)
	gun := filepath.Dir(keyPath)[1:]
	fmt.Printf("%s %s\n", gun, fingerprint)
}

func askConfirm() bool {
	var res string
	_, err := fmt.Scanln(&res)
	if err != nil {
		return false
	}
	if strings.EqualFold(res, "y") || strings.EqualFold(res, "yes") {
		return true
	}
	return false
}
