package data

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
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
	Hash      []byte    `json:"."`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    int64     `json:"."`
	IsExposed bool      `json:"."`
}

type AuthToken struct {
	AccessToken  string `json:"access-token"`
	RefreshToken Token  `json:"refresh-token"`
}

func genereteToken(userID int64, scope string, ttl time.Duration) (*Token, error) {
	token := &Token{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl),
		Scope:     scope,
	}

	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	token.Plaintext = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	hash := sha256.Sum256([]byte(token.Plaintext))
	token.Hash = hash[:]

	return token, nil
}

func ValidateTokenPlaintext(v *validator.Validator, tokenPlaintext string) {
	v.Check(tokenPlaintext != "", "token", "must be provided")
}

type TokenModel struct {
	DB *sql.DB
}

func (m TokenModel) generateJWTToken(userID int64, ttd time.Duration, scope, role string) (string, error) {

	signKey := []byte(Secretkey)
	t := jwt.New(jwt.SigningMethodHS256)
	claims := t.Claims.(jwt.MapClaims)

	claims["scope"] = scope
	claims["user_id"] = userID
	claims["role"] = role
	claims["exp"] = time.Now().Add(ttd).Unix()

	tokenString, err := t.SignedString(signKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

func (m TokenModel) NewAuthToken(user User, ttlAccess, ttlRefresh time.Duration) (interface{}, error) {
	accessToken, err := m.generateJWTToken(user.ID, ttlAccess, TypeAccess, user.Role)

	if err != nil || accessToken == "" {
		return "", err
	}

	refreshToken, err := m.NewToken(user, TypeRefresh, ttlRefresh)
	if err != nil {
		return "", err
	}

	return AuthToken{AccessToken: accessToken, RefreshToken: *refreshToken}, nil

}

func (m TokenModel) NewToken(user User, scope string, ttl time.Duration) (*Token, error) {

	token, err := genereteToken(user.ID, scope, ttl)
	if err != nil {
		return nil, err
	}

	err = m.Insert(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (m TokenModel) Insert(token *Token) error {
	query := `
		INSERT INTO tokens (hash, user_id, expiry, scope)
		VALUES ($1, $2, $3, $4)`
	args := []interface{}{token.Hash, token.UserID, token.ExpiresAt, token.Scope}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := m.DB.ExecContext(ctx, query, args...)
	return err
}

func (m TokenModel) SetExposed(user *User) error {
	query := `	UPDATE tokens 
				SET is_exposed = true 
				WHERE user_id = $1`

	_, err := m.DB.Exec(query, user)
	if err != nil {
		return err
	}
	return nil
}

func (m TokenModel) GetAllForUser(user *User) ([]*Token, error) {
	query := `SELECT hash, user_login, expiry, scope
			FROM tokens
			WHERE user_id = $1 
			AND expiry > $2
			AND is_exposed = false`

	args := []interface{}{user.ID, time.Now()}

	rows, err := m.DB.Query(query, args...)

	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var tokens []*Token
	for rows.Next() {
		var tempToken Token
		err = rows.Scan(&tempToken.Hash, &tempToken.UserID, &tempToken.ExpiresAt, &tempToken.Scope)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, &tempToken)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (m TokenModel) DeleteAllForUser(scope string, userID int64) error {
	query := `
		DELETE FROM tokens
		WHERE scope = $1 AND user_id = $2`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := m.DB.ExecContext(ctx, query, scope, userID)
	return err
}
