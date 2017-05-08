package setup

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/docker/notary"
	grpcauth "github.com/docker/notary/auth/grpc"
	"github.com/docker/notary/auth/token"
	"github.com/docker/notary/client_api/api"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/trustmanager/remoteks"
	"github.com/docker/notary/utils"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	ghealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"net"
	"path/filepath"
)

// the client api will always require push and pull permissions against
// the upstream notary server so at a minimum, all endpoints will request
// these permissions.
var requiredPermissions = []string{"push", "pull"}

func ViperConfig(path string) (*viper.Viper, error) {
	vc := viper.New()
	vc.SetConfigFile(path)
	err := vc.ReadInConfig()
	if err != nil {
		return nil, err
	}
	logrus.Info(vc.AllSettings())
	return vc, nil
}

func NewGRPCServer(addr string, opts []grpc.ServerOption) (*grpc.Server, net.Listener, error) {
	//RPC server setup
	hs := ghealth.NewServer()

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("grpc server failed to listen on %s: %v", addr, err)
	}

	grpcServer := grpc.NewServer(opts...)

	healthpb.RegisterHealthServer(grpcServer, hs)

	return grpcServer, lis, nil
}

func GetAddrAndTLSConfig(vc *viper.Viper) (string, *tls.Config, error) {
	tlsConfig, err := utils.ParseServerTLS(vc, true)
	if err != nil {
		return "", nil, fmt.Errorf("unable to set up TLS: %s", err.Error())
	}

	grpcAddr := vc.GetString("server.grpc_addr")
	if grpcAddr == "" {
		return "", nil, fmt.Errorf("grpc listen address required for server")
	}

	return grpcAddr, tlsConfig, nil
}

func Authorization(vc *viper.Viper) (grpc.UnaryServerInterceptor, error) {
	authType := vc.GetString("auth.type")
	switch authType {
	case notary.AuthTypeToken:
		var (
			realm       = vc.GetString("auth.options.realm")
			service     = vc.GetString("auth.options.service")
			issuer      = vc.GetString("auth.options.issuer")
			rootCAPath  = utils.GetPathRelativeToConfig(vc, "auth.options.rootcertbundle")
			permissions = vc.GetStringMap("auth.options.permissions")
		)
		logrus.Debugf("token realm: %s", realm)
		logrus.Debugf("token service: %s", service)
		logrus.Debugf("token issuer: %s", issuer)
		logrus.Debugf("token ca path: %s", rootCAPath)
		tokenAuth, err := token.NewAuth(realm, issuer, service, rootCAPath)
		if err != nil {
			return nil, err
		}
		basePerms := api.DefaultPermissions()
		basePerms, err = mergePermissions(basePerms, permissions)
		if err != nil {
			return nil, err
		}
		return grpcauth.NewServerAuthorizer(tokenAuth, basePerms)

	case "":
		// no auth configured
		return nil, nil
	}
	return nil, fmt.Errorf("unrecognized authorization type: %s", authType)
}

func KeyStorage(vc *viper.Viper) ([]trustmanager.KeyStore, error) {
	var (
		keyStore trustmanager.KeyStore
		err      error
		location = vc.GetString("key_storage.type")
		secret   = vc.GetString("key_storage.secret")
	)
	if secret == "" {
		return nil, errors.New("must set a key_storage.secret")
	}
	switch location {
	case "local":
		baseDir := vc.GetString("key_storage.directory")
		if baseDir == "" {
			return nil, errors.New("local key storage selected but no key_storage.directory included in configuration")
		}
		keyStore, err = trustmanager.NewKeyFileStore(filepath.Join(baseDir, notary.PrivDir), passphrase.ConstantRetriever(secret))
		if err != nil {
			return nil, err
		}
	case "memory":
		keyStore = trustmanager.NewKeyMemoryStore(passphrase.ConstantRetriever(secret))
	case "remote":
		tlsOpts, err := utils.ParseTLS(vc, "key_storage", true)
		if err != nil {
			return nil, err
		}
		tlsConfig, err := tlsconfig.Client(tlsOpts)
		if err != nil {
			return nil, err
		}
		store, err := remoteks.NewRemoteStore(
			vc.GetString("key_storage.addr"),
			tlsConfig,
			vc.GetDuration("key_storage.timeout"),
		)
		if err != nil {
			return nil, err
		}
		keyStore = trustmanager.NewGenericKeyStore(store, passphrase.ConstantRetriever(secret))
	default:
		return nil, errors.New("no key storage configured")
	}
	return []trustmanager.KeyStore{keyStore}, nil
}

func mergePermissions(basePerms map[string][]string, additional map[string]interface{}) (map[string][]string, error) {
	for k, v := range basePerms {
		if more, ok := additional[k]; ok {
			add, ok := more.([]string)
			if !ok {
				return basePerms, fmt.Errorf("additional permissions for %s could not be parsed as a list of strings", k)
			}
			basePerms[k] = append(v, add...)
		}
	}
	return basePerms, nil
}
