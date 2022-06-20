package models

type RefreshToken struct {
	ID        string `gorm:"primary_key"`
	ClientID  string `gorm:"not null"`
	Subject   string `gorm:"not null; index"`
	Signature string `gorm:"not null; index"`
	Scope     string `gorm:"not null"`
	IssuedAt  int64  `gorm:"not null"`
	ExpiresAt int64  `gorm:"not null"`
}
