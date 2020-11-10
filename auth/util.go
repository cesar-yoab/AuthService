package auth

import (
	"log"
	"os"
	"regexp"
	"time"

	"github.com/cesar-yoab/authService/graph/model"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/crypto/bcrypt"
)

// getFromEnv the value given a key from a .env file
func getFromEnv(key string) string {
	// Load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal(err)
	}

	return os.Getenv(key)
}

// generateToken given a set of claims
func generateToken(claims jwt.MapClaims) (string, error) {
	// Get signing key
	secret := getFromEnv("KEY")
	if secret == "" {
		log.Fatal("Could not get hold of signing KEY")
	}

	// Create a new token object
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// HashPassword given password string. This function is a wrapper to the bcrypt GenerateFromPassword
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// ValidUserInput validates given passwords, email and username
func ValidUserInput(input *model.RegisterInput) (bool, error) {
	// Check both passwords are equal
	if input.Password != input.ConfirmPassword {
		return false, gqlerror.Errorf("Passwords must match.")
	}

	// Length of password in no bigger than 100 characters
	if len(input.Password) > 100 {
		return false, gqlerror.Errorf("Password is too long.")
	}

	// Check for a valid email address
	if !IsValidEmail(input.Email) {
		return false, gqlerror.Errorf("Invalid email address.")
	}

	// Valid user input
	return true, nil
}

// ValidateAndPrepare user input for insertion to database
func ValidateAndPrepare(registerInput *model.RegisterInput) (*model.RegisterInput, error) {
	if b, err := ValidUserInput(registerInput); !b { // Validate input
		return nil, err
	}

	// Hash both passwords
	password, err := HashPassword(registerInput.Password)
	if err != nil {
		return nil, err
	}

	confPass, err := HashPassword(registerInput.ConfirmPassword)
	if err != nil {
		return nil, err
	}

	// Return same information but now passwords are hashed and ready
	// to be stored in database
	return &model.RegisterInput{
		Fname:           registerInput.Fname,
		Lname:           registerInput.Lname,
		Email:           registerInput.Email,
		Password:        password,
		ConfirmPassword: confPass,
		Username:        registerInput.Username,
	}, nil
}

// IsValidEmail returns true if its a valid syntax email
//  code taken from: https://golangcode.com/validate-an-email-address/
func IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if len(email) < 3 && len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}

// ComparePasswords to check if they are equivalent
func ComparePasswords(hashedpassword, password []byte) bool {
	comp := bcrypt.CompareHashAndPassword(hashedpassword, password)
	if comp != nil {
		return false
	}

	return true
}

// RefreshJWT Provides a new token provided it has a least a minute left of lifetime
func RefreshJWT(token *model.RefreshToken) (*model.Token, error) {
	// We don't include the error because we deal with this kind of error with gqlerror
	tkn, _ := jwt.Parse(token.OldToken, func(token *jwt.Token) (interface{}, error) {
		// Validate alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, gqlerror.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// Get the secret
		secret := getFromEnv("KEY")
		if secret == "" {
			return nil, gqlerror.Errorf("Server error could not issue new token.")
		}

		// Return the secret with bytes
		return []byte(secret), nil
	})

	// Check validity of token
	if !tkn.Valid {
		return nil, gqlerror.Errorf("Invalid token")
	}

	// Get the payload to parse and generate a new token
	claims, ok := tkn.Claims.(jwt.MapClaims)
	if !ok {
		return nil, gqlerror.Errorf("Unexpected error parsing claims.")
	}

	// If passwords match then we issue a token for the user
	newToken, err := generateToken(jwt.MapClaims{
		"_id":      claims["_id"],
		"username": claims["username"],
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	if err != nil {
		return nil, gqlerror.Errorf("Server error could not generate a new token.")
	}

	// Finally return a token for graphql
	return &model.Token{
		Jwt: newToken,
	}, nil
}
