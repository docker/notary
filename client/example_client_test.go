package client

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/theupdateframework/notary/trustmanager/grpckeystore"
	"github.com/theupdateframework/notary/trustpinning"
	"github.com/theupdateframework/notary/tuf/data"
)

func Example() {
	rootDir := ".trust"
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		panic(err)
	}

	server := "https://notary.docker.io"
	image := "docker.io/library/alpine"
	repo, err := NewFileCachedRepository(
		rootDir,
		data.GUN(image),
		server,
		makeHubTransport(server, image),
		nil,
		trustpinning.TrustPinConfig{},
		grpckeystore.GRPCClientConfig{},
	)
	if err != nil {
		panic(err)
	}

	targets, err := repo.ListTargets()
	if err != nil {
		panic(err)
	}

	for _, tgt := range targets {
		fmt.Printf("%s\t%s\n", tgt.Name, hex.EncodeToString(tgt.Hashes["sha256"]))
	}
}

func makeHubTransport(server, image string) http.RoundTripper {
	base := http.DefaultTransport
	modifiers := []transport.RequestModifier{
		transport.NewHeaderRequestModifier(http.Header{
			"User-Agent": []string{"my-client"},
		}),
	}

	authTransport := transport.NewTransport(base, modifiers...)
	pingClient := &http.Client{
		Transport: authTransport,
		Timeout:   5 * time.Second,
	}
	req, err := http.NewRequest("GET", server+"/v2/", nil)
	if err != nil {
		panic(err)
	}

	challengeManager := challenge.NewSimpleManager()
	resp, err := pingClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if err := challengeManager.AddResponse(resp); err != nil {
		panic(err)
	}
	tokenHandler := auth.NewTokenHandler(base, nil, image, "pull")
	modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, tokenHandler, auth.NewBasicHandler(nil)))

	return transport.NewTransport(base, modifiers...)
}
