package main

import (
	"fmt"
	"idas/config"
	"idas/crypto"
	"idas/models"
	"idas/server"
	"idas/store"
	"net/http"
	"os"
	"runtime"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load environment variables if not starting from docker image
	if runtime.GOOS == "windows" {
		err := godotenv.Load()
		if err != nil {
			return err
		}
	}

	// Load certificates
	crypto.InitialiseCertificates()

	dsn := os.Getenv("DSN")
	db, err := setupDatabase(dsn)
	if err != nil {
		return err
	}

	// Setup the in memory cache for requests, providers.
	cache := store.NewMapCache()

	// Setup a server
	srv := server.NewServer()
	srv.SetDB(db)

	srv.SetCache(cache)
	srv.RegisterProviders()

	srv.SetConfig(config.NewServerMetadata())

	// Setup CORS
	handler := cors.AllowAll().Handler(srv)

	// TODO: Setup TLS
	return http.ListenAndServe("127.0.0.1:8080", handler)
}

func setupDatabase(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&models.User{})
	db.AutoMigrate(&models.Client{})
	db.AutoMigrate(&models.RefreshToken{})

	return db, nil
}
