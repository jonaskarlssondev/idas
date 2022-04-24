package grants

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt"
)

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectUri  string
	ClientId     string
	CodeVerifier string
}

type IssuedRefreshToken struct {
	refreshToken         string
	IssuedAt             int64
	refreshTokenLifetime int64
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// Token processes requests to the /token endpoint.
//
// It currently only supports the 'authorization_code' grant type.
func Token(s *Store, r *TokenRequest) (*TokenResponse, *ErrorResponse) {
	var issued *IssuedRefreshToken
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

	s.RefreshTokens[issued.refreshToken] = *issued

	return &TokenResponse{
		AccessToken:  token,
		RefreshToken: issued.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "",
	}, nil
}

func AuthorizationCodeGrantType(s *Store, r *TokenRequest) (*IssuedRefreshToken, string, *ErrorResponse) {
	var issued IssuedRefreshToken

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

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString([]byte("secret"))
	if err != nil {
		fmt.Print("Error signing token: ", err)

		return &issued, "", &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "The authorization server failed to generate tokens.",
		}
	}

	refreshToken := generateCode(32)

	issued = IssuedRefreshToken{
		refreshToken:         refreshToken,
		refreshTokenLifetime: 7776000, // 90 days
		IssuedAt:             jwt.TimeFunc().Unix(),
	}

	fmt.Printf("Issued tokens: %+v\n and access token: %s", issued, token)
	return &issued, token, nil
}

func generateChallenge(verifier string) string {
	sha256 := sha256.Sum256([]byte(verifier))
	response := base64.URLEncoding.EncodeToString(sha256[:])

	// Remove trailing '=' from base64 encoding
	return response[:len(response)-1]
}

func validateTokenRequest(r *TokenRequest, acca *AuthorizationCodeChallengeAssociation) *ErrorResponse {
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

func validateCodeChallenge(r *TokenRequest, acca *AuthorizationCodeChallengeAssociation) *ErrorResponse {
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
