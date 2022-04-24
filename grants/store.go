package grants

type Store struct {
	Acca          map[string]AuthorizationCodeChallengeAssociation
	RefreshTokens map[string]IssuedRefreshToken
}

func NewStore() *Store {
	return &Store{
		Acca:          make(map[string]AuthorizationCodeChallengeAssociation),
		RefreshTokens: make(map[string]IssuedRefreshToken),
	}
}
