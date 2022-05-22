package oauth

import "testing"

func TestInvalidRequests(t *testing.T) {
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
		err := validateAuthorizationRequest(&r)
		if err == nil {
			t.Errorf("Expected error for request: %+v", r)
		}
	}
}
