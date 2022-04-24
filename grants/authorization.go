package grants

import (
	"math/rand"
	"time"
)

type AuthorizationRequest struct {
	ResponseType        string
	ClientId            string
	RedirectUri         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type AuthorizationCodeChallengeAssociation struct {
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	ClientId            string
	RedirectUri         string
}

type AuthorizationResponse struct {
	Code  string
	State string
}

// Authorization is the entry point for the authorization grant process.
//
// It currently only supports the "code" response type as part of the authorization code flow with PKCE.
// The code is valid for 1 minute.
func Authorization(s *Store, r *AuthorizationRequest) (*AuthorizationResponse, *ErrorResponse) {
	if r.CodeChallengeMethod == "" {
		r.CodeChallengeMethod = "plain"
	}

	authzError := validateAuthorizationRequest(r)
	if authzError != nil {
		return nil, authzError
	}

	code := generateCode(32)

	state := AuthorizationCodeChallengeAssociation{
		Code:                code,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		Scope:               r.Scope,
		ClientId:            r.ClientId,
		RedirectUri:         r.RedirectUri,
	}

	s.Acca[code] = state

	defer func() {
		go sleepDelete(s, code)
	}()

	return &AuthorizationResponse{
		Code:  code,
		State: r.State,
	}, nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateCode(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func sleepDelete(s *Store, code string) {
	time.Sleep(time.Minute)
	delete(s.Acca, code)
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func validateAuthorizationRequest(r *AuthorizationRequest) *ErrorResponse {
	if r.ResponseType != "code" {
		return &ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "Only the 'code' response type is supported",
		}
	}
	if r.ClientId == "" {
		// TODO: Check if client is registered
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