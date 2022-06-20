package models

type User struct {
	ID       string `gorm:"primary_key"`
	Name     string `gorm:"not null"`
	GithubId string
}
