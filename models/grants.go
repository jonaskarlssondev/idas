package models

// Authorization code flow cross-request information
type AuthorizationCodeChallenge struct {
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string
	ClientId            string
	RedirectUri         string
	Scope               string
	State               string
	Sub                 string
}
