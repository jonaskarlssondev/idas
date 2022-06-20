package models

type AuthorizationRequest struct {
	Provider    *Provider
	State       string
	CallbackUri string
}
