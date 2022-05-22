package oauth

import (
	"idas/clients"
	"idas/crypto"
	"idas/external"
	"idas/store"
	"net/http"
	"net/url"
)

// Authorization code flow request input
type AuthorizationRequest struct {
	ResponseType        string
	ClientId            string
	RedirectUri         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func AuthorizationEndpoint(w http.ResponseWriter, r *http.Request, s *store.Store) *ErrorResponse {
	// Confirm client is registered
	client, ok := s.Clients[r.FormValue("client_id")]
	if !ok {
		return &ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "The client is not registered.",
		}
	}

	// Make sure the request is will eventually return to a valid endpoint
	redirect_uri, err := url.Parse(r.FormValue("redirect_uri"))
	if err != nil || client.RedirectUri != redirect_uri.String() {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect_uri",
		}
	}

	req := &AuthorizationRequest{
		ResponseType:        r.FormValue("response_type"),
		ClientId:            r.FormValue("client_id"),
		RedirectUri:         redirect_uri.String(),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	if req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = "plain"
	}

	authzError := validateAuthorizationRequest(req)
	if authzError != nil {
		return authzError
	}

	var provider clients.Provider
	// Custom optional property for requesting an external provider
	if r.FormValue("provider") != "" {
		provider, ok = s.Providers[r.FormValue("provider")]
		if !ok {
			return &ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "The requested provider is not registered.",
			}
		}
	} else {
		// TODO: Let user select provider
		// For now, default to github
		provider = *clients.Github()
	}

	acca := store.AuthorizationCodeChallengeAssociation{
		Code:                "",
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Scope:               req.Scope,
		ClientId:            req.ClientId,
		RedirectUri:         req.RedirectUri,
		State:               req.State,
	}

	providerState := crypto.GenerateCode(16)

	s.AuthCodeAssociation[providerState] = acca
	s.Requests[providerState] = store.Requests{
		RequestType: store.Provider,
		Provider:    provider,
	}

	extReq := external.AuthorizationRequest{
		Provider: provider,
		State:    providerState,
	}

	external.Challenge(w, r, &extReq)

	return nil
}

// Checks for the existing and valid request parameters and responds aligned with 5.2. of RFC 6749
func validateAuthorizationRequest(r *AuthorizationRequest) *ErrorResponse {
	if r.ResponseType != "code" {
		return &ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "Only the 'code' response type is supported",
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
