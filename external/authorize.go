package external

import (
	"idas/clients"
	"idas/settings"
	"net/http"
)

type AuthorizationRequest struct {
	Provider clients.Provider
	State    string
}

func Challenge(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) {
	// TODO: Build request based on authorization type

	redirectUri := settings.AuthzServerMetadata.SignInCallbackUri

	url := req.Provider.AuthorizationEndpoint +
		"?client_id=" + req.Provider.ClientId +
		"&redirect_uri=" + redirectUri +
		"&scope=" + req.Provider.Scope +
		"&state=" + req.State

	http.Redirect(w, r, url, http.StatusFound)
}
