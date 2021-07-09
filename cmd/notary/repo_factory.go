package main

import (
	"github.com/spf13/viper"

	"net/http"

	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/tuf/data"
)

const remoteConfigField = "api"

// RepoFactory takes a GUN and returns an initialized client.Repository, or an error.
type RepoFactory func(gun data.GUN) (client.Repository, error)

// ConfigureRepo takes in the configuration parameters and returns a repoFactory that can
// initialize new client.Repository objects with the correct upstreams and password
// retrieval mechanisms.
func ConfigureRepo(v *viper.Viper, retriever notary.PassRetriever, onlineOperation bool, permission httpAccess) RepoFactory {
	localRepo := func(gun data.GUN) (client.Repository, error) {
		var rt http.RoundTripper
		trustPin, err := getTrustPinning(v)
		if err != nil {
			return nil, err
		}
		if onlineOperation {
			rt, err = getTransport(v, gun, permission)
			if err != nil {
				return nil, err
			}
		}
		return client.NewFileCachedRepository(
			v.GetString("trust_dir"),
			gun,
			getRemoteTrustServer(v),
			rt,
			retriever,
			trustPin,
			getGRPCKeyStore(v),
		)
	}

	return localRepo
}
