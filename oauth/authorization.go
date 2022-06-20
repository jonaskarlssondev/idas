package oauth

import (
	"idas/crypto"
	"idas/models"
	"idas/store"
	"net/http"
	"net/url"
	"time"
)

// authorizationRequest ...
type authorizationRequest struct {
	ResponseType        string
	ClientId            string
	RedirectUri         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func Authorize(cache *store.Cache, c *models.Client, w http.ResponseWriter, r *http.Request) (*models.AuthorizationRequest, *ErrorResponse) {
	req := decode(r)

	err := validate(req, c)
	if err != nil {
		return nil, err
	}

	// Let users request a specific external identity provider
	providerKey := r.FormValue("provider")
	if providerKey == "" {
		providerKey = "github"
	}

	provider, ok := cache.Providers[providerKey]
	if !ok {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The requested provider is not registered.",
		}
	}

	// Generate state against 3rd party, which is the key to both the client incoming request, and the external outbound request.
	state := crypto.GenerateCode(16)

	// generate authorization code and save it to the cache
	code := crypto.GenerateCode(16)

	// Persist until return from 3rd party auth OR a minute has passed.
	cache.AuthorizationCodeChallenge[state] = &models.AuthorizationCodeChallenge{
		Code:                code,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ClientId:            req.ClientId,
		RedirectUri:         req.RedirectUri,
		Scope:               req.Scope,
		State:               req.State,
	}

	// Delete code after 1 minute
	go func() {
		time.Sleep(time.Minute)
		delete(cache.AuthorizationCodeChallenge, state)
	}()

	// Generate and cache request against 3rd party identity provider
	request := &models.AuthorizationRequest{
		Provider: provider,
		State:    state,
	}

	cache.ExternalRequests[state] = request

	return request, nil
}

// decode ...
func decode(r *http.Request) *authorizationRequest {
	req := &authorizationRequest{
		ResponseType:        r.FormValue("response_type"),
		ClientId:            r.FormValue("client_id"),
		RedirectUri:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	if req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = "plain"
	}

	return req
}

// validate checks for the existing and valid request parameters and responds aligned with 5.2 of RFC 6749
func validate(r *authorizationRequest, c *models.Client) *ErrorResponse {
	if r.ResponseType != "code" {
		return &ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "Only the 'code' response type is supported.",
		}
	}

	if r.ClientId == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'client_id' parameter is required.",
		}
	}

	if r.RedirectUri == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'redirect_uri' parameter is required.",
		}
	}

	// Make sure the request will eventually return to a valid endpoint
	redirect_uri, err := url.Parse(r.RedirectUri)
	if err != nil || c.RedirectUri != redirect_uri.String() {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect_uri",
		}
	}

	if r.State == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "For increased security, the 'state' parameter is required.",
		}
	}

	if r.CodeChallenge == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "For increased security, PKCE is required. Please set the 'code_challenge' parameter.",
		}
	}

	if r.CodeChallengeMethod != "S256" && r.CodeChallengeMethod != "plain" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid 'code_challenge_method' parameter. Valid values are 'plain' and 'S256'.",
		}
	}

	return nil
}
