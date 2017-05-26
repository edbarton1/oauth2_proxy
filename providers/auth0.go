package providers

import (
        "errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/bitly/oauth2_proxy/api"
)

type Auth0Provider struct {
	*ProviderData
	Tenant string
}

func NewAuth0Provider(p *ProviderData) *Auth0Provider {

	p.ProviderName = "Auth0"
	if p.Scope == "" {
		p.Scope = "openid profile"
	}
	return &Auth0Provider{ProviderData: p}
}

func (p *Auth0Provider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "undefined_tenant"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
                        Host:   p.Tenant + ".auth0.com",
			Path:   "/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
                        Host:   p.Tenant + ".auth0.com",
			Path:   "/oauth/token",
		}
	}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
                        Host:   p.Tenant + ".auth0.com",
			Path:   "/userinfo",
		}
	}

}

func getAuth0Header(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *Auth0Provider) GetEmailAddress(s *SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAuth0Header(s.AccessToken)

	json, err := api.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}
	flag, err := json.Get("email_verified").Bool()
	if err == nil && flag == true {
		return json.Get("email").String()
	}
	log.Printf("email is not verified")
	return "", nil
}
