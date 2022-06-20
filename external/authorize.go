package external

import (
	"idas/models"
	"net/http"
)

func Challenge(w http.ResponseWriter, r *http.Request, req *models.AuthorizationRequest) {
	redirectUri := req.CallbackUri

	url := req.Provider.AuthorizationEndpoint +
		"?client_id=" + req.Provider.ClientId +
		"&redirect_uri=" + redirectUri +
		"&scope=" + req.Provider.Scope +
		"&state=" + req.State

	http.Redirect(w, r, url, http.StatusFound)
}
