package main

import (
	"encoding/json"
	"fmt"
	"idas/grants"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

var store = grants.NewStore()

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", home).Methods("GET")

	r.HandleFunc("/authorize", authorization).Methods("GET")
	r.HandleFunc("/token", token).Methods("POST")

	handler := cors.Default().Handler(r)
	// TODO: Set up TLS
	err := http.ListenAndServe("127.0.0.1:8080", handler)
	if err != nil {
		panic(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Identity and Authentication Server!"))
}

func authorization(w http.ResponseWriter, r *http.Request) {
	redirect_uri, err := url.Parse(r.FormValue("redirect_uri"))
	if err != nil {
		authzError := grants.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect_uri",
		}

		WriteResponse(w, authzError, http.StatusBadRequest)
		return
	}

	req := &grants.AuthorizationRequest{
		ResponseType:        r.FormValue("response_type"),
		ClientId:            r.FormValue("client_id"),
		RedirectUri:         redirect_uri.String(),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	response, authzError := grants.Authorization(store, req)

	if authzError != nil {
		WriteResponse(w, authzError, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	url := req.RedirectUri + "?code=" + response.Code + "&state=" + req.State

	http.Redirect(w, r, url, http.StatusFound)
}

func token(w http.ResponseWriter, r *http.Request) {
	// If the code exists, it should be deleted to prevent replay attacks
	code := r.FormValue("code")
	defer delete(store.Acca, code)

	_, ok := store.Acca[code]

	// Validate that the code has been persisted as part of previous request and hasn't expired yet.
	if !ok {
		WriteResponse(w, grants.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid code.",
		}, http.StatusBadRequest)
		return
	}

	// Parse redirect uri from the url encoded format.
	redirect_uri, err := url.Parse(r.FormValue("redirect_uri"))
	if err != nil {
		WriteResponse(w, grants.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect_uri.",
		}, http.StatusBadRequest)
		return
	}

	req := &grants.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         code,
		RedirectUri:  redirect_uri.String(),
		ClientId:     r.FormValue("client_id"),
		CodeVerifier: r.FormValue("code_verifier"),
	}

	response, reqErr := grants.Token(store, req)
	if err != nil {
		WriteResponse(w, *reqErr, http.StatusBadRequest)
		return
	}

	fmt.Printf("Response: %+v\n", response)
	fmt.Printf("Error: %+v\n", reqErr)
	WriteResponse(w, response, http.StatusOK)
}

func WriteResponse(w http.ResponseWriter, resp interface{}, status int) {
	if status == http.StatusBadRequest {
		log.Printf("Error on request: %s\n", resp)
	}

	response, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to convert response to json: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal_server_error"))
	}

	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
