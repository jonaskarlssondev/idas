package config

type AuthorizationServerMetadata struct {
	SignInCallbackUri string
}

func NewServerMetadata() *AuthorizationServerMetadata {
	return &AuthorizationServerMetadata{
		SignInCallbackUri: "http://localhost:8080/oauth/external/callback",
	}
}
