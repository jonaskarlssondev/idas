package oauth

import (
	"idas/crypto"
	"idas/models"
	"idas/store"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
)

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func UserInfo(db *store.DB, w http.ResponseWriter, r *http.Request) (*Profile, *ErrorResponse) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Failed to extract access token from request.",
		}
	}

	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return crypto.GetSigningKey(), nil
	})

	id := claims["sub"].(string)

	var user models.User
	err := db.Users.First(&user, "id = ?", id).Error

	if err != nil {
		return nil, &ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The requested provider is not registered.",
		}
	}

	return &Profile{
		ID:   user.ID,
		Name: user.Name,
	}, nil
}
