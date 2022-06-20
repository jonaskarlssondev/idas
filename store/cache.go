package store

import (
	"idas/models"
)

type cache[T any] map[string]T

type Cache struct {
	Providers                  cache[*models.Provider]
	ExternalRequests           cache[*models.AuthorizationRequest]
	AuthorizationCodeChallenge cache[*models.AuthorizationCodeChallenge]
}

func NewMapCache() *Cache {
	return &Cache{
		Providers:                  make(cache[*models.Provider]),
		ExternalRequests:           make(cache[*models.AuthorizationRequest]),
		AuthorizationCodeChallenge: make(cache[*models.AuthorizationCodeChallenge]),
	}
}

func (c *Cache) AddGithub() {
	c.Providers["github"] = models.Github()
}
