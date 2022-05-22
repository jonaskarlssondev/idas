package main

import (
	"encoding/json"
	"idas/clients"
	"idas/external"
	"idas/oauth"
	s "idas/store"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

var store s.Store

func init() {
	store = *s.NewStore()
	store.Clients["bird"] = clients.Client{
		ClientId:    "bird",
		RedirectUri: "http://localhost:3000/auth/callback/bird",
	}
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", home).Methods("GET")

	r.HandleFunc("/oauth/authorize", authorization).Methods("GET")
	r.HandleFunc("/oauth/token", token).Methods("POST")

	r.HandleFunc("/oauth/external/callback", callback).Methods("GET")

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
	authzError := oauth.AuthorizationEndpoint(w, r, &store)
	if authzError != nil {
		writeResponse(w, authzError, http.StatusBadRequest)
	}
}

func token(w http.ResponseWriter, r *http.Request) {
	response, authzError := oauth.TokenEndpoint(w, r, &store)
	if authzError != nil {
		writeResponse(w, authzError, http.StatusBadRequest)
	}

	writeResponse(w, response, http.StatusOK)
}

func callback(w http.ResponseWriter, r *http.Request) {
	err := external.CallbackEndpoint(w, r, &store)
	if err != nil {
		writeResponse(w, err, http.StatusBadRequest)
	}
}

func writeResponse(w http.ResponseWriter, resp interface{}, status int) {
	if status == http.StatusBadRequest {
		log.Printf("Error on request: %s\n", resp)
	}

	response, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to convert response to json: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal_server_error"))
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
