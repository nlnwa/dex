package pilt

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Config holds configuration options for Pilt logins.
type Config struct {
	Issuer      string `json:"issuer"`
	RedirectURI string `json:"redirectURI"`

	Scopes []string `json:"scopes"` // defaults to "profile" and "email"
}

// Open returns a connector which can be used to login users through an upstream
// Pilt provider.
func (c *Config) Open(id string, logger log.Logger) (conn connector.Connector, err error) {
	issuerUrl, err := url.Parse(c.Issuer)
	if err != nil {
		return "", fmt.Errorf("failed to parse issuerURL %q: %v", c.Issuer, err)
	}

	if !strings.HasSuffix(issuerUrl.Path, "/") {
		issuerUrl.Path = issuerUrl.Path + "/"
	}

	login, _ := url.Parse("login.html")
	session, _ := url.Parse("api/v1/session")
	groups, _ := url.Parse("api/v1/group")
	authEndpoint := issuerUrl.ResolveReference(login)
	sessionEndpoint := issuerUrl.ResolveReference(session)
	groupsEndpoint := issuerUrl.ResolveReference(groups)

	return &piltConnector{
		redirectURI:     c.RedirectURI,
		authEndpoint:    authEndpoint.String(),
		sessionEndpoint: sessionEndpoint.String(),
		groupsEndpoint:  groupsEndpoint.String(),
		logger:          logger,
	}, nil
}

var (
	_ connector.CallbackConnector = (*piltConnector)(nil)
	_ connector.RefreshConnector  = (*piltConnector)(nil)
)

type piltConnector struct {
	redirectURI     string
	authEndpoint    string
	sessionEndpoint string
	groupsEndpoint  string
	ctx             context.Context
	cancel          context.CancelFunc
	logger          log.Logger
	hostedDomains   []string
}

func (c *piltConnector) Close() error {
	c.cancel()
	return nil
}

func (c *piltConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()

	a := c.authEndpoint + "?returnTo=" + u.String()

	return a, nil
}

type piltError struct {
	error            string
	errorDescription string
}

func (e *piltError) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *piltConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()

	if errType := q.Get("error"); errType != "" {
		return identity, &piltError{errType, q.Get("error_description")}
	}

	ssoCookie, err := r.Cookie("nbsso")
	if err != nil {
		return identity, fmt.Errorf("pilt: failed to get token: %v", err)
	}

	if err := getSession(c, &identity, ssoCookie); err != nil {
		return identity, err
	}
	if err := getGroups(c, &identity, ssoCookie); err != nil {
		return identity, err
	}

	c.logger.Debugf("Identity: %v", identity)
	return identity, nil
}

func getSession(c *piltConnector, identity *connector.Identity, ssoCookie *http.Cookie) (err error) {
	req, err := http.NewRequest("GET", c.sessionEndpoint, nil)
	req.AddCookie(ssoCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// handle error
		return fmt.Errorf("pilt: failed to get user session: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	c.logger.Debugf("Session response: %v", body)
	var msg interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		// handle error
		return fmt.Errorf("pilt: failed to decode session data: %v", err)
	}
	m := msg.(map[string]interface{})
	eud := m["extendedUserData"].(map[string]interface{})
	idps := eud["identityProviderData"].([]interface{})
	firstIdp := idps[0].(map[string]interface{})

	uid := eud["userId"].(string)
	user := firstIdp["firstName"].(string) + " " + firstIdp["lastName"].(string)
	email := firstIdp["emailAddress"].(string)

	identity.UserID = uid
	identity.Username = user
	identity.Email = email

	return nil
}

func getGroups(c *piltConnector, identity *connector.Identity, ssoCookie *http.Cookie) (err error) {
	g := c.groupsEndpoint + "?forUserId=" + identity.UserID
	req, err := http.NewRequest("GET", g, nil)
	req.AddCookie(ssoCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// handle error
		return fmt.Errorf("pilt: failed to get user groups: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	c.logger.Debugf("Group response: %v", body)
	var msg []string
	if err := json.Unmarshal(body, &msg); err != nil {
		// handle error
		return fmt.Errorf("pilt: failed to decode user groups: %v", err)
	}

	identity.Groups = msg

	return nil
}

// Refresh is implemented for backwards compatibility, even though it's a no-op.
func (c *piltConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	return identity, nil
}
