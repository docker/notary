package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
)

// Stolen from a mix of UCP + nautilus signer, some might be able to be cleaned up / streamlined
type credentialStore struct {
	username      string
	password      string
	refreshTokens map[string]string
}

func (tcs *credentialStore) Basic(url *url.URL) (string, string) {
	return tcs.username, tcs.password
}

// refresh tokens are the long lived tokens that can be used instead of a password
func (tcs *credentialStore) RefreshToken(u *url.URL, service string) string {
	return tcs.refreshTokens[service]
}

func (tcs *credentialStore) SetRefreshToken(u *url.URL, service string, token string) {
	if tcs.refreshTokens != nil {
		tcs.refreshTokens[service] = token
	}
}

// GetReadOnlyAuthTransport gets the Garant Auth Transport used to communicate with notary
func GetReadOnlyAuthTransport(server string, scopes []string, username, password, rootCAPath string) (http.RoundTripper, error) {
	httpsTransport, err := httpsTransport(rootCAPath, "", "")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v2/", server), nil)
	if err != nil {
		return nil, err
	}
	pingClient := &http.Client{
		Transport: httpsTransport,
		Timeout:   5 * time.Second,
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		return nil, err
	}
	challengeManager := challenge.NewSimpleManager()
	if err := challengeManager.AddResponse(resp); err != nil {
		return nil, err
	}

	creds := credentialStore{
		username:      username,
		password:      password,
		refreshTokens: make(map[string]string),
	}

	var scopeObjs []auth.Scope
	for _, scopeName := range scopes {
		scopeObjs = append(scopeObjs, auth.RepositoryScope{
			Repository: scopeName,
			Actions:    []string{"pull"},
		})
	}

	// allow setting multiple scopes so we don't have to reauth
	tokenHandler := auth.NewTokenHandlerWithOptions(auth.TokenHandlerOptions{
		Transport:   httpsTransport,
		Credentials: &creds,
		Scopes:      scopeObjs,
	})

	authedTransport := transport.NewTransport(httpsTransport, auth.NewAuthorizer(challengeManager, tokenHandler))
	return authedTransport, nil
}

// GetForwardingAuthTransport returns an http.RoundTripper that fowards the provided token
// to the end service. It is assumed the token already carries the necessary authorization
// scope to perform the action required of that end service.
// It is presumed tokens is simply taken directly from the http.Header on an incoming request
// to the intermediate service and requires no additional formatting.
func GetForwardingAuthTransport(rootCAPath string, tokens []string) (http.RoundTripper, error) {
	httpsTransport, err := httpsTransport(rootCAPath, "", "")
	if err != nil {
		return nil, err
	}
	tokenHeader := http.Header{
		"Authorization": tokens,
	}
	return transport.NewTransport(httpsTransport, transport.NewHeaderRequestModifier(tokenHeader)), nil
}

func httpsTransport(caFile, clientCertFile, clientKeyFile string) (*http.Transport, error) {
	tlsConfig := &tls.Config{}
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
	// Override with the system cert pool if the caFile was empty
	if caFile == "" {
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig.RootCAs = systemCertPool
	} else {
		certs, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certs) {
			return nil, fmt.Errorf("failed to fully parse %s", caFile)
		}
		transport.TLSClientConfig.RootCAs = pool

	}
	return &transport, nil
}
