package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

var (
	signing_cert *x509.Certificate
	signing_key  *rsa.PrivateKey
)

// Returns the public certificate used for token signing.
func GetSigningCert() *x509.Certificate {
	return signing_cert
}

// Returns the private key used for token signing.
func GetSigningKey() *rsa.PrivateKey {
	return signing_key
}

// Load certificates before starting the server.
func InitialiseCertificates() {
	cert, err := loadCert(os.Getenv("SIGNING_CERT_PATH"))
	if err != nil {
		panic(err)
	}

	key, err := loadKey(os.Getenv("SIGNING_KEY_PATH"))
	if err != nil {
		panic(err)
	}

	var rsaKey *rsa.PrivateKey
	var ok bool
	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		panic(errors.New("invalid key format"))
	}

	signing_cert = cert
	signing_key = rsaKey
}

// loadCert loads a x509 certificate in ASN.1 DER form from a relative file path.
func loadCert(path string) (*x509.Certificate, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(file)
	if block == nil {
		panic("failed to decode PEM block.")
	}

	// Will only return data if no errors.
	return x509.ParseCertificate(block.Bytes)
}

// loadKey loads an unencrypted private key in PKCS #8, ASN.1 DER form from the relative file path.
func loadKey(path string) (any, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(file)
	if block == nil {
		panic("failed to decode PEM block.")
	}

	// Will only return data if no errors.
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seed = rand.New(rand.NewSource(time.Now().UnixNano()))

// GenerateCode generates an n length string picking from the given assortment in [A-Za-z0-9]
func GenerateCode(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[seed.Intn(len(letterBytes))]
	}
	return string(b)
}
