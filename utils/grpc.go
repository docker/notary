package utils

import (
	"crypto/tls"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/go-connections/tlsconfig"
	auth "github.com/docker/notary/auth/client"
	"github.com/docker/notary/auth/grpc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"strings"
)

// sets up TLS for the GRPC connection to notary-signer
func grpcTLS(configuration *viper.Viper, prefix string) (*tls.Config, error) {
	rootCA := GetPathRelativeToConfig(
		configuration,
		strings.Join([]string{prefix, "tls_ca_file"}, "."),
	)
	clientCert := GetPathRelativeToConfig(
		configuration,
		strings.Join([]string{prefix, "tls_client_cert"}, "."),
	)
	clientKey := GetPathRelativeToConfig(
		configuration,
		strings.Join([]string{prefix, "tls_client_key"}, "."),
	)

	if clientCert == "" && clientKey != "" || clientCert != "" && clientKey == "" {
		return nil, fmt.Errorf("either pass both client key and cert, or neither")
	}

	tlsConfig, err := tlsconfig.Client(tlsconfig.Options{
		CAFile:   rootCA,
		CertFile: clientCert,
		KeyFile:  clientKey,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"Unable to configure TLS to the client API gRPC service: %s", err.Error())
	}

	return tlsConfig, nil
}

func GetGRPCClient(vc *viper.Viper, prefix string, credStore auth.CredentialStore) (*grpc.ClientConn, error) {
	var (
		dialOpts = []grpc.DialOption{
			grpc.WithBlock(),
		}
		tlsConfig *tls.Config
		err       error
	)
	addr := vc.GetString(
		strings.Join(
			[]string{prefix, "addr"},
			".",
		),
	)

	if vc.GetBool(
		strings.Join(
			[]string{prefix, "insecure"},
			".",
		),
	) {
		logrus.Warn("setting insecure connection")
		dialOpts = append(dialOpts, grpc.WithInsecure())
	} else {
		tlsConfig, err = grpcTLS(vc, prefix)
		if err != nil {
			logrus.Warn(err)
			dialOpts = append(dialOpts, grpc.WithInsecure())
		} else {
			creds := credentials.NewTLS(tlsConfig)
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
		}
	}
	dialOpts = append(dialOpts, grpc.WithUnaryInterceptor(grpcauth.NewClientAuthorizer(credStore)))

	return grpc.Dial(addr, dialOpts...)
}
