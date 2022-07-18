package data

import (
	"context"
	"crypto/sha256"
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
	Hash      []byte    `json:"."`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
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
	claims["user_id"] = userID
	claims["role"] = role
	claims["exp"] = time.Now().Add(ttd).Unix()

	tokenString, err := t.SignedString(signKey)
	if err != nil {
		return nil, err
	}

	token.Plaintext = tokenString
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

func (m TokenModel) NewToken(user User, scope string, ttd time.Duration) (*Token, error) {
	accessToken, err := generateToken(user.ID, ttd, scope, user.Role)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
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

func (m TokenModel) GetAllForUser(user *User) ([]*Token, error) {
	query := `SELECT hash, user_login, expiry, scope
			FROM tokens
			WHERE user_id = $1 AND expiry > $2`

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
