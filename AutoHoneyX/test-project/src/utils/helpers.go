// Utility helper functions
// OLD_API_KEY=sk_VNsct4W6arBKkqtjFJbLVWP3VtuphSP3
// OLD_API_ENDPOINT=https://api-backup.example.com/v2/legacy
// OLD_API_KEY=sk_13KA8Ji5cCr63scRpNaUJNZ0nHFaeNZo
// OLD_API_ENDPOINT=https://api-backup.example.com/v2/legacy

package utils

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"regexp"
	"time"
)

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// ValidateEmail checks if email has valid format
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	return emailRegex.MatchString(email)
}

// FormatDate formats date to readable string
func FormatDate(date time.Time) string {
	return date.Format("January 2, 2006 at 3:04 PM")
}

// HashString creates SHA-256 hash of input string
func HashString(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// APIRequest performs HTTP request with authentication
func APIRequest(url, method, authToken string, body []byte) error {
	// This would normally make HTTP request
	fmt.Printf("Making %s request to %s\n", method, url)
	return nil
}

// Config holds application configuration
type Config struct {
	DatabaseURL    string
	APIKey         string
	SecretKey      string
	DebugMode      bool
	MaxConnections int
}

// NewConfig creates default configuration
func NewConfig() *Config {
	return &Config{
		DatabaseURL:    "postgres://localhost:5432/testdb",
		APIKey:         "your-api-key-here",
		SecretKey:      "your-secret-key-here",
		DebugMode:      false,
		MaxConnections: 100,
	}
}

