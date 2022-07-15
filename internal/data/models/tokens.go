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
	Secretkey           = "mysecret"
	accessTokenExp      = time.Minute * 15
	refreshTokenExp     = time.Hour * 25 * 7
)

type Token struct {
	Plaintext string    `json:"token"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires+at"`
	UserID    int64     `json:"."`
}

func generateToken(userID int64, ttd time.Duration, scope, role string) (*Token, error) {
	token := &Token{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttd),
		Scope:     scope,
	}

	signKey := []byte(Secretkey)
	t := jwt.New(jwt.SigningMethodHS256)
	claims := t.Claims.(jwt.MapClaims)

	claims["scope"] = scope
	claims["userid"] = userID
	claims["role"] = role
	claims["exp"] = time.Now().Add(ttd)

	tokenString, err := t.SignedString(signKey)
	if err != nil {
		return nil, err
	}

	token.Plaintext = tokenString
	return token, nil

}

func ValidateTokenPlaintext(v *validator.Validator, tokenPlaintext string) {
	v.Check(tokenPlaintext != "", "token", "must be provided")
}

type TokenModel struct {
	DB *sql.DB
}

func (m TokenModel) NewToken(user User, scope string, ttd time.Duration) (*Token, error) {
	token, err := generateToken(user.ID, ttd, scope, user.Role)
	if err != nil {
		return nil, err
	}

	return token, nil
}
