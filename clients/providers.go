package clients

import "os"

// Client information
type Provider struct {
	Id                    string
	ClientId              string
	ClientSecret          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	RedirectUri           string
	Scope                 string
}

func Github() *Provider {
	return &Provider{
		ClientId:              os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret:          os.Getenv("GITHUB_CLIENT_SECRET"),
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		Scope:                 "read:user",
	}
}
