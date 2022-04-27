package endpoints

import (
	"crypto/sha256"
	"encoding/base64"
	"idas/crypto"
	"idas/store"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt"
)

// Token endpoint request input
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectUri  string
	ClientId     string
	CodeVerifier string
}

// Token endpoint response output
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func TokenEndpoint(w http.ResponseWriter, r *http.Request, s *store.Store) (*TokenResponse, *ErrorResponse) {
	// If the code exists, it should be deleted to prevent replay attacks
	code := r.FormValue("code")
	defer delete(s.Acca, code)

	_, ok := s.Acca[code]

	// Validate that the code has been persisted as part of previous request and hasn't expired yet.
	if !ok {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid code.",
		}
	}

	// Parse redirect uri from the url encoded format.
	redirect_uri, err := url.Parse(r.FormValue("redirect_uri"))
	if err != nil {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect_uri.",
		}
	}

	req := &TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         code,
		RedirectUri:  redirect_uri.String(),
		ClientId:     r.FormValue("client_id"),
		CodeVerifier: r.FormValue("code_verifier"),
	}

	return token(s, req)

}

// Token processes requests to the /token endpoint.
//
// It currently only supports the 'authorization_code' grant type.
func token(s *store.Store, r *TokenRequest) (*TokenResponse, *ErrorResponse) {
	var issued *store.IssuedRefreshToken
	var token string
	var err *ErrorResponse

	switch r.GrantType {
	case "authorization_code":
		issued, token, err = AuthorizationCodeGrantType(s, r)
	default:
		return nil, &ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "The provided grant type is not supported.",
		}
	}

	if err != nil {
		return nil, err
	}

	s.RefreshTokens[issued.RefreshToken] = *issued

	return &TokenResponse{
		AccessToken:  token,
		RefreshToken: issued.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "",
	}, nil
}

// AuthorizationCodeGrantType processes requests to the /token endpoint for the 'authorization_code' grant type.
func AuthorizationCodeGrantType(s *store.Store, r *TokenRequest) (*store.IssuedRefreshToken, string, *ErrorResponse) {
	var issued store.IssuedRefreshToken

	acca, ok := s.Acca[r.Code]
	if !ok {
		return &issued, "", &ErrorResponse{
			Error:            "invalid_requst",
			ErrorDescription: "Invalid 'code' parameter.",
		}
	}

	reqErr := validateTokenRequest(r, &acca)
	if reqErr != nil {
		return &issued, "", reqErr
	}

	reqErr = validateCodeChallenge(r, &acca)
	if reqErr != nil {
		return &issued, "", reqErr
	}

	claims := &jwt.StandardClaims{
		Audience:  "bird",
		ExpiresAt: jwt.TimeFunc().Unix() + 3600,
		IssuedAt:  jwt.TimeFunc().Unix(),
		Issuer:    "IDAS",
		Subject:   r.ClientId,
	}

	at := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token, err := at.SignedString(crypto.GetSigningKey())
	if err != nil {
		return &issued, "", &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "The authorization server failed to generate tokens.",
		}
	}

	refreshToken := generateCode(32)

	issued = store.IssuedRefreshToken{
		RefreshToken:         refreshToken,
		RefreshTokenLifetime: 7776000, // 90 days
		IssuedAt:             jwt.TimeFunc().Unix(),
	}

	return &issued, token, nil
}

func generateChallenge(verifier string) string {
	sha256 := sha256.Sum256([]byte(verifier))
	response := base64.URLEncoding.EncodeToString(sha256[:])

	// Remove trailing '=' from base64 encoding
	return response[:len(response)-1]
}

func validateTokenRequest(r *TokenRequest, acca *store.AuthorizationCodeChallengeAssociation) *ErrorResponse {
	if r.Code == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'code' parameter is required.",
		}
	}

	if r.RedirectUri == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'redirect_uri' parameter is required.",
		}
	}

	if r.ClientId == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'client_id' parameter is required.",
		}
	}

	if r.CodeVerifier == "" {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'code_verifier' parameter is required.",
		}
	}

	if acca.RedirectUri != r.RedirectUri {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'redirect_uri' parameter is not valid.",
		}
	}

	return nil
}

func validateCodeChallenge(r *TokenRequest, acca *store.AuthorizationCodeChallengeAssociation) *ErrorResponse {
	if acca.CodeChallengeMethod == "S256" {
		challenge := generateChallenge(r.CodeVerifier)

		if challenge != acca.CodeChallenge {
			return &ErrorResponse{
				Error:            "access_denied",
				ErrorDescription: "The code verifier did not evaluate to the correct challenge.",
			}
		}
	} else {
		if r.CodeVerifier != acca.CodeChallenge {
			return &ErrorResponse{
				Error:            "access_denied",
				ErrorDescription: "The code verifier did not evaluate to the correct challenge.",
			}
		}
	}

	return nil
}
