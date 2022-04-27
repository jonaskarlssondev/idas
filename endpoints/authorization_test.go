package endpoints

import (
	"idas/store"
	"testing"
)

func TestValidRequests(t *testing.T) {
	s := store.NewStore()
	requests := []AuthorizationRequest{
		{
			ResponseType:        "code",
			ClientId:            "client_id",
			RedirectUri:         "url",
			State:               "state",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "plain",
		},
		{
			ResponseType:        "code",
			ClientId:            "client_id",
			RedirectUri:         "url",
			State:               "state",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "plain",
		},
	}

	for _, r := range requests {
		response, err := authorization(s, &r)
		if err != nil {
			t.Errorf("Did not expect an error: %+v", err)
		}

		gotState := response.State
		wantState := r.State

		gotCode := response.Code
		dontWantCode := ""

		if gotState != wantState {
			t.Errorf("Expected state to be '%s', got '%s'", wantState, gotState)
		}

		if gotCode == dontWantCode {
			t.Errorf("Expected code to not be '%s', got '%s'", dontWantCode, gotCode)
		}
	}
}

func TestInvalidRequests(t *testing.T) {
	s := store.NewStore()
	requests := []AuthorizationRequest{
		{
			ResponseType: "not_code",
		},
		{
			ResponseType: "code",
		},
		{
			ResponseType: "code",
			ClientId:     "client_id",
			RedirectUri:  "",
		},
		{
			ResponseType: "code",
			ClientId:     "client_id",
			RedirectUri:  "url",
		},
		{
			ResponseType: "code",
			ClientId:     "client_id",
			RedirectUri:  "url",
			State:        "",
		},
		{
			ResponseType: "code",
			ClientId:     "client_id",
			RedirectUri:  "url",
			State:        "state",
		},
	}

	for _, r := range requests {
		_, err := authorization(s, &r)
		if err == nil {
			t.Errorf("Expected error for request: %+v", r)
		}
	}
}
