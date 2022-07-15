package data

import (
	"database/sql"
	"time"

	"github.com/binsabit/authorization_practice/internal/data/validator"
	"github.com/golang-jwt/jwt"
)

const (
	ScopeActivation     = "activation"
	ScopeAuthentication = "authentication"
	TypeAccess          = "access"
	TypeRefresh         = "refresh"
	secretkey           = "mysecret"
	accessTokenExp      = time.Minute * 15
	refreshTokenExp     = time.Hour * 25 * 7
)

type Token struct {
	Plaintext string    `json:"token"`
	Hash      []byte    `json:"."`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires+at"`
	UserID    int64     `json:"."`
}

func generateToken(userID int64, ttd time.Duration, scope, role string) (string, error) {
	signKey := []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["scope"] = scope
	claims["userid"] = userID
	claims["role"] = role
	claims["exp"] = time.Now().Add(ttd)

	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateTokenPlaintext(v *validator.Validator, tokenPlaintext string) {
	v.Check(tokenPlaintext != "", "token", "must be provided")
}

type TokenModel struct {
	DB *sql.DB
}

func (m TokenModel) New(user User, scope string)
