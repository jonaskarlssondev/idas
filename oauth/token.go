package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"idas/crypto"
	"idas/models"
	"idas/store"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// Token endpoint request input
type tokenRequest struct {
	GrantType    string
	Code         string
	RedirectUri  string
	ClientID     string
	CodeVerifier string
	Scope        string

	RefreshToken string
}

// Token endpoint response output
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func Token(db *store.DB, cache *store.Cache, w http.ResponseWriter, r *http.Request) (*TokenResponse, *ErrorResponse) {
	grantType := r.FormValue("grant_type")
	if grantType == "" {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid grant_type.",
		}
	}

	var refresh *models.RefreshToken
	var token string
	var errResp *ErrorResponse

	switch grantType {
	case "authorization_code":
		// Parse redirect uri from the url encoded format.
		redirect_uri, err := url.Parse(r.FormValue("redirect_uri"))
		if err != nil {
			return nil, &ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Invalid redirect_uri.",
			}
		}

		req := &tokenRequest{
			GrantType:    r.FormValue("grant_type"),
			Code:         r.FormValue("code"),
			RedirectUri:  redirect_uri.String(),
			ClientID:     r.FormValue("client_id"),
			CodeVerifier: r.FormValue("code_verifier"),
		}

		refresh, token, errResp = authorizationCodeGrantType(db, cache, req)

	case "refresh_token":
		req := &tokenRequest{
			GrantType:    r.FormValue("grant_type"),
			RefreshToken: r.FormValue("refresh_token"),
		}

		refresh, token, errResp = refreshTokenGrantType(db, req)

	default:
		return nil, &ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "The provided grant type is not supported.",
		}
	}

	if errResp != nil {
		return nil, errResp
	}

	return &TokenResponse{
		AccessToken:  token,
		RefreshToken: refresh.Signature,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        refresh.Scope,
	}, nil
}

// AuthorizationCodeGrantType processes requests to the /token endpoint for the 'authorization_code' grant type.
func authorizationCodeGrantType(db *store.DB, cache *store.Cache, r *tokenRequest) (*models.RefreshToken, string, *ErrorResponse) {
	var issued models.RefreshToken
	acc, ok := cache.AuthorizationCodeChallenge[r.Code]
	if !ok {
		return &issued, "", &ErrorResponse{
			Error:            "invalid_requst",
			ErrorDescription: "Invalid 'code' parameter.",
		}
	}
	defer delete(cache.AuthorizationCodeChallenge, r.Code)

	reqErr := validateTokenRequest(r, acc)
	if reqErr != nil {
		return &issued, "", reqErr
	}

	reqErr = validateCodeChallenge(r, acc)
	if reqErr != nil {
		return &issued, "", reqErr
	}

	return createTokens(db, acc.ClientId, acc.Sub, acc.Scope)
}

func createTokens(db *store.DB, clientId, subject, scope string) (*models.RefreshToken, string, *ErrorResponse) {
	var issued models.RefreshToken

	claims := &jwt.StandardClaims{
		Audience:  "bird",
		IssuedAt:  jwt.TimeFunc().Unix(),
		ExpiresAt: jwt.TimeFunc().Unix() + 3600,
		Issuer:    "IDAS",
		Subject:   subject,
	}

	at := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token, err := at.SignedString(crypto.GetSigningKey())
	if err != nil {
		return &issued, "", &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "The authorization server failed to generate tokens.",
		}
	}

	refreshToken := crypto.GenerateCode(32)

	issued = models.RefreshToken{
		ID:        uuid.NewString(),
		Signature: refreshToken,
		ClientID:  clientId,
		Scope:     scope,
		Subject:   subject,
		IssuedAt:  jwt.TimeFunc().Unix(),
		ExpiresAt: jwt.TimeFunc().Unix() + 7776000,
	}

	err = db.RefreshTokens.Create(issued).Error
	if err != nil {
		return &issued, "", &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "The authorization server failed to generate tokens.",
		}
	}

	return &issued, token, nil
}

func generateChallenge(verifier string) string {
	sha256 := sha256.Sum256([]byte(verifier))
	response := base64.URLEncoding.EncodeToString(sha256[:])

	// Remove trailing '=' from base64 encoding
	return response[:len(response)-1]
}

func validateTokenRequest(r *tokenRequest, acc *models.AuthorizationCodeChallenge) *ErrorResponse {
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

	if r.ClientID == "" {
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

	if acc.RedirectUri != r.RedirectUri {
		return &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'redirect_uri' parameter is not valid.",
		}
	}

	return nil
}

func validateCodeChallenge(r *tokenRequest, acc *models.AuthorizationCodeChallenge) *ErrorResponse {
	if acc.CodeChallengeMethod == "S256" {
		challenge := generateChallenge(r.CodeVerifier)

		if challenge != acc.CodeChallenge {
			return &ErrorResponse{
				Error:            "access_denied",
				ErrorDescription: "The code verifier did not evaluate to the correct challenge.",
			}
		}
	} else {
		if r.CodeVerifier != acc.CodeChallenge {
			return &ErrorResponse{
				Error:            "access_denied",
				ErrorDescription: "The code verifier did not evaluate to the correct challenge.",
			}
		}
	}

	return nil
}

func refreshTokenGrantType(db *store.DB, r *tokenRequest) (*models.RefreshToken, string, *ErrorResponse) {
	refresh, errResp := validateRefreshTokenGrant(db, r)
	if errResp != nil {
		return nil, "", errResp
	}

	//TODO: Mark refresh token as used OR delete

	return createTokens(db, refresh.ClientID, refresh.Subject, refresh.Scope)
}

func validateRefreshTokenGrant(db *store.DB, r *tokenRequest) (*models.RefreshToken, *ErrorResponse) {
	if r.GrantType != "refresh_token" {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'grant_type' parameter must be set to 'refresh_token'.",
		}
	}

	if r.RefreshToken == "" {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The 'refresh_token' parameter is required.",
		}
	}

	var refresh models.RefreshToken
	err := db.RefreshTokens.First(&refresh, "signature = ?", r.RefreshToken).Error
	if err != nil {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The refresh token is invalid.",
		}
	}

	if time.Now().Unix() > refresh.ExpiresAt {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The refresh token has expired.",
		}
	}

	return &refresh, nil
}
