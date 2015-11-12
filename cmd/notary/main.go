package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/version"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	configDir        = ".notary/"
	defaultServerURL = "https://notary-server:4443"
	idSize           = 64
)

var (
	rawOutput         bool
	verbose           bool
	trustDir          string
	configFile        string
	remoteTrustServer string
	configPath        string
	configFileName    = "config"
	configFileExt     = "json"
	retriever         passphrase.Retriever
	mainViper         = viper.New()
)

func init() {
	retriever = getPassphraseRetriever()
}

func parseConfig() {
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetOutput(os.Stderr)
	}

	if trustDir == "" {
		// Get home directory for current user
		homeDir, err := homedir.Dir()
		if err != nil {
			fatalf("cannot get current user home directory: %v", err)
		}
		if homeDir == "" {
			fatalf("cannot get current user home directory")
		}
		trustDir = filepath.Join(homeDir, filepath.Dir(configDir))

		logrus.Debugf("no trust directory provided, using default: %s", trustDir)
	} else {
		logrus.Debugf("trust directory provided: %s", trustDir)
	}

	// If there was a commandline configFile set, we parse that.
	// If there wasn't we attempt to find it on the default location ~/.notary/config
	if configFile != "" {
		configFileExt = strings.TrimPrefix(filepath.Ext(configFile), ".")
		configFileName = strings.TrimSuffix(filepath.Base(configFile), filepath.Ext(configFile))
		configPath = filepath.Dir(configFile)
	} else {
		configPath = trustDir
	}

	// Setup the configuration details into viper
	mainViper.SetConfigName(configFileName)
	mainViper.SetConfigType(configFileExt)
	mainViper.AddConfigPath(configPath)

	// Find and read the config file
	err := mainViper.ReadInConfig()
	if err != nil {
		logrus.Debugf("configuration file not found, using defaults")
		// Ignore if the configuration file doesn't exist, we can use the defaults
		if !os.IsNotExist(err) {
			fatalf("fatal error config file: %v", err)
		}
	}
}

func main() {
	var notaryCmd = &cobra.Command{
		Use:   "notary",
		Short: "notary allows the creation of trusted collections.",
		Long:  "notary allows the creation and management of collections of signed targets, allowing the signing and validation of arbitrary content.",
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of notary",
		Long:  `print the version number of notary`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("notary\n Version:    %s\n Git commit: %s\n", version.NotaryVersion, version.GitCommit)
		},
	}

	notaryCmd.AddCommand(versionCmd)

	notaryCmd.PersistentFlags().StringVarP(&trustDir, "trustdir", "d", "", "directory where the trust data is persisted to")
	notaryCmd.PersistentFlags().StringVarP(&configFile, "configFile", "c", "", "path to the configuration file to use")
	notaryCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	notaryCmd.AddCommand(cmdKey)
	notaryCmd.AddCommand(cmdCert)
	notaryCmd.AddCommand(cmdTufInit)
	cmdTufInit.Flags().StringVarP(&remoteTrustServer, "server", "s", "", "Remote trust server location")
	notaryCmd.AddCommand(cmdTufList)
	cmdTufList.Flags().BoolVarP(&rawOutput, "raw", "", false, "Instructs notary list to output a nonpretty printed version of the targets list. Useful if you need to parse the list.")
	cmdTufList.Flags().StringVarP(&remoteTrustServer, "server", "s", "", "Remote trust server location")
	notaryCmd.AddCommand(cmdTufAdd)
	notaryCmd.AddCommand(cmdTufRemove)
	notaryCmd.AddCommand(cmdTufStatus)
	notaryCmd.AddCommand(cmdTufPublish)
	cmdTufPublish.Flags().StringVarP(&remoteTrustServer, "server", "s", "", "Remote trust server location")
	notaryCmd.AddCommand(cmdTufLookup)
	cmdTufLookup.Flags().BoolVarP(&rawOutput, "raw", "", false, "Instructs notary lookup to output a nonpretty printed version of the targets list. Useful if you need to parse the list.")
	cmdTufLookup.Flags().StringVarP(&remoteTrustServer, "server", "s", "", "Remote trust server location")
	notaryCmd.AddCommand(cmdVerify)
	cmdVerify.Flags().StringVarP(&remoteTrustServer, "server", "s", "", "Remote trust server location")

	notaryCmd.Execute()
}

func fatalf(format string, args ...interface{}) {
	fmt.Printf("* fatal: "+format+"\n", args...)
	os.Exit(1)
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

func getPassphraseRetriever() passphrase.Retriever {
	baseRetriever := passphrase.PromptRetriever()
	env := map[string]string{
		"root":     os.Getenv("NOTARY_ROOT_PASSPHRASE"),
		"targets":  os.Getenv("NOTARY_TARGET_PASSPHRASE"),
		"snapshot": os.Getenv("NOTARY_SNAPSHOT_PASSPHRASE"),
	}

	return func(keyName string, alias string, createNew bool, numAttempts int) (string, bool, error) {
		if v := env[alias]; v != "" {
			return v, numAttempts > 1, nil
		}
		return baseRetriever(keyName, alias, createNew, numAttempts)
	}
}
