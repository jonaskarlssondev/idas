package models

// Client
type Client struct {
	ClientId    string `gorm:"primaryKey"`
	Secret      string
	RedirectUri string
	Scope       string
}
