package clients

import "os"

// Client information
type Client struct {
	ClientId              string
	ClientSecret          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	RedirectUri           string
	Scope                 string
}

func Github() *Client {
	return &Client{
		ClientId:              os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret:          os.Getenv("GITHUB_CLIENT_SECRET"),
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		RedirectUri:           "http://localhost:8080/oauth/callback",
		Scope:                 "read:user",
	}
}
