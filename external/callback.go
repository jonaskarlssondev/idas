package external

import (
	"fmt"
	"idas/clients"
	"idas/crypto"
	"idas/settings"
	"idas/store"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func CallbackEndpoint(w http.ResponseWriter, r *http.Request, s *store.Store) *ErrorResponse {
	externalError := r.FormValue("error")
	if externalError != "" {
		return &ErrorResponse{
			Error:            externalError,
			ErrorDescription: r.FormValue("error_description"),
		}
	}

	code := r.FormValue("code")
	state := r.FormValue("state")

	_, ok := s.Requests[state]
	if !ok {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "No active request found for callback.",
		}
	}

	provider := clients.Github()

	// Stop tracking 3rd party request
	delete(s.Providers, state)

	// Build oauth token endpoint request body
	body := url.Values{}
	body.Set("client_id", provider.ClientId)
	body.Set("client_secret", provider.ClientSecret)
	body.Set("code", code)
	body.Set("redirect_uri", settings.AuthzServerMetadata.SignInCallbackUri)

	encodedBody := body.Encode()

	// Exchange code for token
	response, err := http.Post(provider.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(encodedBody))
	if err != nil {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		}
	}

	fmt.Println(response.Body)
	// TODO: Use token to get data

	// TODO: Do this in a nicer, cba atm
	initialRequest := s.AuthCodeAssociation[state]

	// Generate authorization response
	clientResponse := authorization(s, initialRequest)

	delete(s.AuthCodeAssociation, state)

	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	url := clientResponse.RedirectUri + "?code=" + clientResponse.Code + "&state=" + clientResponse.State

	// Return initial authorization endpoint response
	http.Redirect(w, r, url, http.StatusFound)

	return nil
}

// Authorization code flow response output
type AuthorizationResponse struct {
	RedirectUri string
	Code        string
	State       string
}

// authorization generates the response data for the client after a successful 3rd party authorizaton
//
// It currently only supports the "code" response type as part of the authorization code flow with PKCE.
// The code is valid for 1 minute.
func authorization(s *store.Store, acca store.AuthorizationCodeChallengeAssociation) *AuthorizationResponse {
	// generates reasonably random code of length 32.
	code := crypto.GenerateCode(32)

	acca.Code = code

	s.AuthCodeAssociation[code] = acca

	// Delete code after 1 minute
	defer func() {
		go sleepDelete(s, code)
	}()

	return &AuthorizationResponse{
		RedirectUri: acca.RedirectUri,
		Code:        code,
		State:       acca.State,
	}
}

func sleepDelete(s *store.Store, code string) {
	time.Sleep(time.Minute)
	delete(s.AuthCodeAssociation, code)
}
