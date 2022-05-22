package settings

var AuthzServerMetadata = AuthorizationServerMetadata{
	SignInCallbackUri: "http://localhost:8080/oauth/external/callback",
}

type AuthorizationServerMetadata struct {
	SignInCallbackUri string
}
