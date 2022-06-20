package store

import (
	"idas/models"

	"gorm.io/gorm"
)

// DB ...
type DB struct {
	DB            *gorm.DB
	Clients       *gorm.DB
	Users         *gorm.DB
	RefreshTokens *gorm.DB
}

func NewStore(db *gorm.DB) *DB {
	return &DB{
		DB:            db,
		Clients:       db.Model(&models.Client{}),
		Users:         db.Model(&models.User{}),
		RefreshTokens: db.Model(&models.RefreshToken{}),
	}
}
