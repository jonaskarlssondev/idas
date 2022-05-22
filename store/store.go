package store

import "idas/clients"

// Authorization code flow cross-request information
type AuthorizationCodeChallengeAssociation struct {
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	State               string
	ClientId            string
	RedirectUri         string
}

// Refresh token persistence information
type IssuedRefreshToken struct {
	RefreshToken         string
	IssuedAt             int64
	RefreshTokenLifetime int64
}

// RequestType defines the request target
type RequesterType string

const (
	Provider RequesterType = "provider"
	Client   RequesterType = "client"
)

// Requests tracks currently active authorization requests
type Requests struct {
	RequestType RequesterType
	Provider    clients.Provider
	Client      clients.Client
}

// Store is the data store for the authorization server.
type Store struct {
	Clients             map[string]clients.Client
	Providers           map[string]clients.Provider
	Requests            map[string]Requests
	AuthCodeAssociation map[string]AuthorizationCodeChallengeAssociation
	RefreshTokens       map[string]IssuedRefreshToken
}

// Initialises an empty store
func NewStore() *Store {
	return &Store{
		Clients:             make(map[string]clients.Client),
		Providers:           make(map[string]clients.Provider),
		Requests:            make(map[string]Requests),
		AuthCodeAssociation: make(map[string]AuthorizationCodeChallengeAssociation),
		RefreshTokens:       make(map[string]IssuedRefreshToken),
	}
}
