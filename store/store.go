package store

// Authorization code flow cross-request information
type AuthorizationCodeChallengeAssociation struct {
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	ClientId            string
	RedirectUri         string
}

// Refresh token persistence information
type IssuedRefreshToken struct {
	RefreshToken         string
	IssuedAt             int64
	RefreshTokenLifetime int64
}

// Store is the data store for the authorization server.
type Store struct {
	Acca          map[string]AuthorizationCodeChallengeAssociation
	RefreshTokens map[string]IssuedRefreshToken
}

// Initialises an empty store
func NewStore() *Store {
	return &Store{
		Acca:          make(map[string]AuthorizationCodeChallengeAssociation),
		RefreshTokens: make(map[string]IssuedRefreshToken),
	}
}
