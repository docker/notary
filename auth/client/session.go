package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/registry/client"
)

var (
	// ErrNoBasicAuthCredentials is returned if a request can't be authorized with
	// basic auth due to lack of credentials.
	ErrNoBasicAuthCredentials = errors.New("no basic auth credentials")

	// ErrNoToken is returned if a request is successful but the body does not
	// contain an authorization token.
	ErrNoToken = errors.New("authorization server did not include a token in the response")
)

// CredentialStore is an interface for getting credentials for
// a given URL
type CredentialStore interface {
	// Basic returns basic auth for the given URL
	Basic(*url.URL) (string, string)

	// RefreshToken returns a refresh token for the
	// given URL and service
	RefreshToken(*url.URL, string) string

	// SetRefreshToken sets the refresh token if none
	// is provided for the given url and service
	SetRefreshToken(realm *url.URL, service, token string)
}

// This is the minimum duration a token can last (in seconds).
// A token must not live less than 60 seconds because older versions
// of the Docker client didn't read their expiration from the token
// response and assumed 60 seconds.  So to remain compatible with
// those implementations, a token must live at least this long.
const minimumTokenLifetimeSeconds = 60

type TokenHandler struct {
	creds     CredentialStore
	transport http.RoundTripper

	offlineAccess bool
	forceOAuth    bool
	clientID      string
	scopes        []Scope

	tokenLock       sync.Mutex
	tokenCache      string
	tokenExpiration time.Time
}

// Scope is a type which is serializable to a string
// using the allow scope grammar.
type Scope interface {
	String() string
}

// RepositoryScope represents a token scope for access
// to a repository.
type RepositoryScope struct {
	Repository string
	Class      string
	Actions    []string
}

// String returns the string representation of the repository
// using the scope grammar
func (rs RepositoryScope) String() string {
	repoType := "repository"
	if rs.Class != "" {
		repoType = fmt.Sprintf("%s(%s)", repoType, rs.Class)
	}
	return fmt.Sprintf("%s:%s:%s", repoType, rs.Repository, strings.Join(rs.Actions, ","))
}

//// RegistryScope represents a token scope for access
//// to resources in the registry.
//type RegistryScope struct {
//	Name    string
//	Actions []string
//}
//
//// String returns the string representation of the user
//// using the scope grammar
//func (rs RegistryScope) String() string {
//	return fmt.Sprintf("registry:%s:%s", rs.Name, strings.Join(rs.Actions, ","))
//}

// TokenHandlerOptions is used to configure a new token handler
type TokenHandlerOptions struct {
	Transport   http.RoundTripper
	Credentials CredentialStore

	OfflineAccess bool
	ForceOAuth    bool
	ClientID      string
	Scopes        []Scope
}

// NewTokenHandler creates a new AuthenicationHandler which supports
// fetching tokens from a remote token server.
func NewTokenHandler(transport http.RoundTripper, creds CredentialStore, clientID, scope string, actions ...string) *TokenHandler {
	return &TokenHandler{
		transport:     transport,
		creds:         creds,
		offlineAccess: false,
		forceOAuth:    false,
		clientID:      clientID,
		//scopes: []Scope{
		//	RepositoryScope{
		//		Repository: scope,
		//		Actions:    actions,
		//	},
		//},
	}
}

func (th *TokenHandler) client() *http.Client {
	return &http.Client{
		Transport: th.transport,
		Timeout:   15 * time.Second,
	}
}

func (th *TokenHandler) Scheme() string {
	return "bearer"
}

func (th *TokenHandler) AuthorizeRequest(params map[string]string, scopes ...string) (string, error) {
	//th.tokenLock.Lock()
	//defer th.tokenLock.Unlock()

	rawToken, _, err := th.fetchToken(params, scopes)
	return rawToken, err
}

type postTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	Scope        string    `json:"scope"`
}

func (th *TokenHandler) fetchTokenWithOAuth(realm *url.URL, refreshToken, service string, scopes []string) (token string, expiration time.Time, err error) {
	form := url.Values{}
	form.Set("scope", strings.Join(scopes, " "))
	form.Set("service", service)

	clientID := th.clientID
	if clientID == "" {
		// Use default client, this is a required field
		return "", time.Time{}, errors.New("no client ID configured")
	}
	form.Set("client_id", clientID)

	if refreshToken != "" {
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)
	} else if th.creds != nil {
		form.Set("grant_type", "password")
		username, password := th.creds.Basic(realm)
		form.Set("username", username)
		form.Set("password", password)

		// attempt to get a refresh token
		form.Set("access_type", "offline")
	} else {
		// refuse to do oauth without a grant type
		return "", time.Time{}, fmt.Errorf("no supported grant type")
	}

	resp, err := th.client().PostForm(realm.String(), form)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	if !client.SuccessStatus(resp.StatusCode) {
		err := client.HandleErrorResponse(resp)
		return "", time.Time{}, err
	}

	decoder := json.NewDecoder(resp.Body)

	var tr postTokenResponse
	if err = decoder.Decode(&tr); err != nil {
		return "", time.Time{}, fmt.Errorf("unable to decode token response: %s", err)
	}

	if tr.RefreshToken != "" && tr.RefreshToken != refreshToken {
		th.creds.SetRefreshToken(realm, service, tr.RefreshToken)
	}

	if tr.ExpiresIn < minimumTokenLifetimeSeconds {
		// The default/minimum lifetime.
		tr.ExpiresIn = minimumTokenLifetimeSeconds
		logrus.Debugf("Increasing token expiration to: %d seconds", tr.ExpiresIn)
	}

	if tr.IssuedAt.IsZero() {
		// issued_at is optional in the token response.
		tr.IssuedAt = time.Now().UTC()
	}

	return tr.AccessToken, tr.IssuedAt.Add(time.Duration(tr.ExpiresIn) * time.Second), nil
}

type getTokenResponse struct {
	Token        string    `json:"token"`
	AccessToken  string    `json:"access_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshToken string    `json:"refresh_token"`
}

func (th *TokenHandler) fetchTokenWithBasicAuth(realm *url.URL, service string, scopes []string) (token string, expiration time.Time, err error) {

	req, err := http.NewRequest("GET", realm.String(), nil)
	if err != nil {
		return "", time.Time{}, err
	}

	reqParams := req.URL.Query()

	if service != "" {
		reqParams.Add("service", service)
	}

	for _, scope := range scopes {
		reqParams.Add("scope", scope)
	}

	if th.offlineAccess {
		reqParams.Add("offline_token", "true")
		clientID := th.clientID
		if clientID == "" {
			return "", time.Time{}, errors.New("no client ID configured")
		}
		reqParams.Add("client_id", clientID)
	}

	if th.creds != nil {
		username, password := th.creds.Basic(realm)
		if username != "" && password != "" {
			reqParams.Add("account", username)
			req.SetBasicAuth(username, password)
		}
	}

	req.URL.RawQuery = reqParams.Encode()
	logrus.Infof("requesting token for following permissions: %s", req.URL.RawQuery)

	resp, err := th.client().Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	if !client.SuccessStatus(resp.StatusCode) {
		err := client.HandleErrorResponse(resp)
		return "", time.Time{}, err
	}

	decoder := json.NewDecoder(resp.Body)

	var tr getTokenResponse
	if err = decoder.Decode(&tr); err != nil {
		return "", time.Time{}, fmt.Errorf("unable to decode token response: %s", err)
	}

	if tr.RefreshToken != "" && th.creds != nil {
		th.creds.SetRefreshToken(realm, service, tr.RefreshToken)
	}

	// `access_token` is equivalent to `token` and if both are specified
	// the choice is undefined.  Canonicalize `access_token` by sticking
	// things in `token`.
	if tr.AccessToken != "" {
		tr.Token = tr.AccessToken
	}

	if tr.Token == "" {
		return "", time.Time{}, ErrNoToken
	}

	if tr.ExpiresIn < minimumTokenLifetimeSeconds {
		// The default/minimum lifetime.
		tr.ExpiresIn = minimumTokenLifetimeSeconds
		logrus.Debugf("Increasing token expiration to: %d seconds", tr.ExpiresIn)
	}

	if tr.IssuedAt.IsZero() {
		// issued_at is optional in the token response.
		tr.IssuedAt = time.Now().UTC()
	}

	return tr.Token, tr.IssuedAt.Add(time.Duration(tr.ExpiresIn) * time.Second), nil
}

func (th *TokenHandler) fetchToken(params map[string]string, scopes []string) (token string, expiration time.Time, err error) {
	realm, ok := params["realm"]
	if !ok {
		return "", time.Time{}, errors.New("no realm specified for token auth challenge")
	}

	// TODO(dmcgowan): Handle empty scheme and relative realm
	realmURL, err := url.Parse(realm)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid token auth challenge realm: %s", err)
	}

	service := params["service"]

	var refreshToken string

	if th.creds != nil {
		refreshToken = th.creds.RefreshToken(realmURL, service)
	}

	if refreshToken != "" || th.forceOAuth {
		return th.fetchTokenWithOAuth(realmURL, refreshToken, service, scopes)
	}

	return th.fetchTokenWithBasicAuth(realmURL, service, scopes)
}
