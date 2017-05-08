package main

import (
	"github.com/spf13/viper"

	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/client_api/api"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/utils"
	"net/http"
	"github.com/docker/notary/auth/grpc"
)

const remoteConfigField = "api"

type repoFactory func(gun data.GUN) (client.Repository, error)

func ConfigureRepo(v *viper.Viper, retriever notary.PassRetriever, onlineOperation bool) repoFactory {
	localRepo := func(gun data.GUN) (client.Repository, error) {
		var rt http.RoundTripper
		trustPin, err := getTrustPinning(v)
		if err != nil {
			return nil, err
		}
		if onlineOperation {
			rt, err = getTransport(v, gun, admin)
			if err != nil {
				return nil, err
			}
		}
		return client.NewFileCachedNotaryRepository(
			v.GetString("trust_dir"),
			gun,
			getRemoteTrustServer(v),
			rt,
			retriever,
			trustPin,
		)
	}

	remoteRepo := func(gun data.GUN) (client.Repository, error) {
		conn, err := utils.GetGRPCClient(
			v,
			remoteConfigField,
			grpcauth.NewCredStore(&passwordStore{false}, nil, nil),
		)
		if err != nil {
			return nil, err
		}
		return api.NewClient(conn, gun), nil
	}

	if v.IsSet(remoteConfigField) {
		return remoteRepo
	}
	return localRepo
}
