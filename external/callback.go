package external

import (
	"encoding/json"
	"fmt"
	"idas/config"
	"idas/models"
	"idas/store"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// Authorization code flow response output
type AuthorizationResponse struct {
	RedirectUri string
	Code        string
	State       string
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func Callback(db *store.DB, cache *store.Cache, meta *config.AuthorizationServerMetadata, w http.ResponseWriter, r *http.Request) (*AuthorizationResponse, *ErrorResponse) {
	// Validate authorization at 3rd party
	externalError := r.FormValue("error")
	if externalError != "" {
		return nil, &ErrorResponse{
			Error:            externalError,
			ErrorDescription: r.FormValue("error_description"),
		}
	}

	code := r.FormValue("code")
	state := r.FormValue("state")

	req, ok := cache.ExternalRequests[state]
	if !ok {
		return nil, &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "No active request found for callback.",
		}
	}
	delete(cache.ExternalRequests, state)

	// On succesful 3rd issuing of auth code, exchange code for access token.
	tokenResponse, err := exchangeCode(req.Provider, meta, code)
	if err != nil {
		return nil, &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to exchange code for token at 3rd party.",
		}
	}

	// Extract basic user info required to
	userResponse, err := fetchUserInfo(req.Provider, tokenResponse.AccessToken)
	if err != nil {
		return nil, &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to fetch username and id from 3rd party.",
		}
	}

	// Fetch or create user if not exists
	user, err := getOrCreateUser(db, userResponse, req)
	if err != nil {
		return nil, &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to create new user after 3rd party authentication.",
		}
	}

	// Switch key to remember until request comes back
	acc, ok := cache.AuthorizationCodeChallenge[state]
	if !ok {
		return nil, &ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Could not find a started authentication challenge from client after callback from 3rd party.",
		}
	}

	delete(cache.AuthorizationCodeChallenge, state)
	acc.Sub = user.ID
	cache.AuthorizationCodeChallenge[acc.Code] = acc

	return &AuthorizationResponse{
		RedirectUri: acc.RedirectUri,
		Code:        acc.Code,
		State:       acc.State,
	}, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func exchangeCode(p *models.Provider, meta *config.AuthorizationServerMetadata, code string) (*tokenResponse, error) {
	// Build oauth token endpoint request body
	body := url.Values{}
	body.Set("client_id", p.ClientId)
	body.Set("client_secret", p.ClientSecret)
	body.Set("code", code)
	body.Set("redirect_uri", meta.SignInCallbackUri)

	encodedBody := body.Encode()

	// Exchange code for token
	request, err := http.NewRequest("POST", p.TokenEndpoint, strings.NewReader(encodedBody))
	if err != nil {
		return nil, err
	}

	// Send as form data to follow RFC. Request to receive response as json
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var tokenResponse tokenResponse
	err = json.NewDecoder(response.Body).Decode(&tokenResponse)
	if err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

type userResponse struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

func fetchUserInfo(p *models.Provider, token string) (*userResponse, error) {
	userReq, err := http.NewRequest("GET", p.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}

	userReq.Header.Add("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(userReq)
	if err != nil {
		return nil, err
	}

	var userResponse userResponse
	err = json.NewDecoder(response.Body).Decode(&userResponse)
	if err != nil {
		return nil, err
	}

	return &userResponse, nil
}

func getOrCreateUser(db *store.DB, res *userResponse, req *models.AuthorizationRequest) (*models.User, error) {
	var user models.User
	err := db.Users.First(&user, "github_id = ?", fmt.Sprint(res.Id)).Error

	if err != nil {
		user = models.User{
			ID:       uuid.NewString(),
			Name:     res.Name,
			GithubId: fmt.Sprint(res.Id),
		}

		fmt.Printf("Creating new user id: %s for id: %s\n", user.ID, user.GithubId)

		err = db.DB.Create(&user).Error
	}

	return &user, err
}
