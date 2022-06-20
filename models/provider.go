package models

import "os"

// Provider contains information
type Provider struct {
	ID                    string
	ClientId              string
	ClientSecret          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	RedirectUri           string
	Scope                 string
}

func Github() *Provider {
	return &Provider{
		ClientId:              os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret:          os.Getenv("GITHUB_CLIENT_SECRET"),
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		UserInfoEndpoint:      "https://api.github.com/user",
		Scope:                 "read:user",
	}
}
