package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	notaryclient "github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/tuf/data"
)

type diffCommander struct {
	// these need to be set
	configGetter func() (*viper.Viper, error)
}

var cmdDiffTemplate = usageTemplate{
	Use:   "diff [ GUN ] [ timestamp hash ] [ timestamp hash ]",
	Short: "Display the difference between two versions of a notary repo.",
	Long:  "Display the difference in two versions of the same notary repo. Versions are specific by the hashes of their timestamps which can be found by using the changefeed.",
}

func (d *diffCommander) AddToCommand(cmd *cobra.Command) {
	cmd.AddCommand(cmdDiffTemplate.ToCommand(d.diff))
}

func (d *diffCommander) diff(cmd *cobra.Command, args []string) error {
	if len(args) < 3 {
		cmd.Usage()
		return fmt.Errorf("Must specify a GUN and two timestamp hashes")
	}
	config, err := d.configGetter()
	if err != nil {
		return err
	}
	gun := data.GUN(args[0])
	hash1 := args[1]
	hash2 := args[2]

	baseURL := getRemoteTrustServer(config)

	rt, err := getTransport(config, gun, admin)
	if err != nil {
		return err
	}

	diff, err := notaryclient.NewDiff(gun, baseURL, rt, hash1, hash2)
	if err != nil {
		return err
	}
	out, err := json.Marshal(diff)
	if err != nil {
		return err
	}
	cmd.Println(string(out))
	return nil
}
