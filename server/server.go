package server

import (
	"encoding/json"
	"fmt"
	"idas/config"
	"idas/external"
	"idas/models"
	"idas/oauth"
	"idas/store"
	"net/http"
	"os"

	"gorm.io/gorm"
)

type server struct {
	db     *store.DB
	cache  *store.Cache
	router *http.ServeMux

	config *config.AuthorizationServerMetadata
}

func NewServer() *server {
	s := &server{}
	s.router = http.NewServeMux()
	s.routes()

	return s
}

func (s *server) SetDB(db *gorm.DB) {
	s.db = store.NewStore(db)
}

func (s *server) SetCache(c *store.Cache) {
	s.cache = c
}

func (s *server) RegisterProviders() {
	s.cache.AddGithub()
}

func (s *server) SetConfig(c *config.AuthorizationServerMetadata) {
	s.config = c
}

// ServeHTTP enables the server to act as an http.Handler
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// routes sets up all the HTTP routes for the server.
func (s *server) routes() {
	s.router.HandleFunc("/", s.index)

	s.router.HandleFunc("/oauth/authorize", s.handleOauthAuthorize)
	s.router.HandleFunc("/oauth/token", s.handleOauthToken)

	s.router.HandleFunc("/oauth/external/callback", s.handleOauthExternalCallback)

	s.router.HandleFunc("/oauth/userinfo", s.handleUserInfo)
}

// index shows the default home page
func (s *server) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Identity and Authentication Server!"))
}

// handleOauthAuthorize
func (s *server) handleOauthAuthorize(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("client_id")

	// Validate that request conforms to a valid registered client
	var client *models.Client
	err := s.db.Clients.First(&client, "client_id = ?", id).Error

	if err != nil {
		s.respond(w, oauth.ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: fmt.Sprintf("The client '%s' is not registered.", id),
		}, http.StatusBadRequest)
	}

	// Validate the OAuth request and return a 3rd party authorization request if so.
	request, oauthErr := oauth.Authorize(s.cache, client, w, r)
	if oauthErr != nil {
		s.respond(w, err, http.StatusBadRequest)
	}

	request.CallbackUri = s.config.SignInCallbackUri

	// Redirect client to 3rd party identity provider
	external.Challenge(w, r, request)
}

func (s *server) handleOauthExternalCallback(w http.ResponseWriter, r *http.Request) {
	resp, err := external.Callback(s.db, s.cache, s.config, w, r)
	if err != nil {
		s.respond(w, err, http.StatusInternalServerError)
	}

	url := resp.RedirectUri + "?code=" + resp.Code + "&state=" + resp.State

	http.Redirect(w, r, url, http.StatusFound)
}

func (s *server) handleOauthToken(w http.ResponseWriter, r *http.Request) {
	resp, err := oauth.Token(s.db, s.cache, w, r)
	if err != nil {
		s.respond(w, err, http.StatusInternalServerError)
	}

	s.respond(w, resp, http.StatusOK)
}

func (s *server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	resp, err := oauth.UserInfo(s.db, w, r)
	if err != nil {
		s.respond(w, err, http.StatusInternalServerError)
	}

	s.respond(w, resp, http.StatusOK)
}

func (s *server) respond(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	if data != nil {
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	}
}
