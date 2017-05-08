package main

import (
	"flag"
	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/client"
	"github.com/docker/notary/client_api/api"
	"github.com/docker/notary/cmd/clientapi/setup"
	"github.com/docker/notary/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	configPath string
)

func init() {
	flag.StringVar(
		&configPath,
		"config",
		"config.toml",
		"path to configuration file; supported formats are JSON, YAML, and TOML",
	)
	flag.Parse()
	client.SetServerManagesSnapshot()
}

func main() {
	vc, err := setup.ViperConfig(configPath)
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.SetLevel(logrus.DebugLevel)

	// FIXME: refactor with notary-signer/config.go:getAddrAndTLSConfig()
	// and setupGRPCServer()
	grpcAddr, tlsConfig, err := setup.GetAddrAndTLSConfig(vc)
	if err != nil {
		logrus.Fatalf("unable to set up TLS: %s", err.Error())
	}

	upstreamAddr := vc.GetString("upstream.addr")
	upstreamCAPath := utils.GetPathRelativeToConfig(vc, "upstream.tls_ca_file")

	creds := credentials.NewTLS(tlsConfig)
	auth, err := setup.Authorization(vc)
	if err != nil {
		logrus.Fatalf("unable to configure authorization: %s", err.Error())
	}

	opts := []grpc.ServerOption{
		grpc.Creds(creds),
	}
	if auth != nil {
		opts = append(opts, grpc.UnaryInterceptor(auth))
	}

	srv, lis, err := setup.NewGRPCServer(grpcAddr, opts)
	if err != nil {
		logrus.Fatalf("grpc server failed to start on %s: %v",
			grpcAddr, err)
	}
	keyStorage, err := setup.KeyStorage(vc)
	if err != nil {
		logrus.Fatalf("failed to configure key storage: %s", err.Error())
	}
	err = api.NewServer(upstreamAddr, upstreamCAPath, srv, keyStorage)
	if err != nil {
		logrus.Fatal(err)
	}

	srv.GetServiceInfo()

	logrus.Infof("serving on %s", grpcAddr)
	if err := srv.Serve(lis); err != nil {
		logrus.Errorf("server stopped with an error: %v", err)
	}
	logrus.Info("server shutting down")
}
