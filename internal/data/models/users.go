package data

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/binsabit/authorization_practice/internal/data/validator"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrDuplicateLogin = errors.New("duplicate login")
)
var AnonymousUser = &User{}

type User struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Login     string    `json:"login"`
	Password  password  `json:"."`
	Status    string    `json:"status"`
	Role      string    `json:"role"`
	Name      string    `json:"name"`
}

type password struct {
	plaintext *string
	hash      []byte
}

func (u *User) IsAnonymous() bool {
	return u == AnonymousUser
}

func ValidateLogin(v *validator.Validator, login string) {
	v.Check(login != "", "login", "must be provided")
	v.Check(len(login) >= 5, "login", "must be at least 5 bytes long")
}
func ValidatePasswordPlaintext(v *validator.Validator, password string) {
	v.Check(password != "", "password", "must be provided")
	v.Check(len(password) >= 8, "password", "must be at least 8 bytes long")
}
func ValidateUser(v *validator.Validator, user *User) {

	ValidateLogin(v, user.Login)

	if user.Password.plaintext != nil {
		ValidatePasswordPlaintext(v, *user.Password.plaintext)
	}

	if user.Password.hash == nil {
		panic("missing password hash for user")
	}
}

func (p *password) Set(plaintextPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), 12)
	if err != nil {
		return err
	}
	p.plaintext = &plaintextPassword
	p.hash = hash
	return nil
}
func (p *password) Matches(plaintextPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(p.hash, []byte(plaintextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, err
		default:
			return false, err
		}
	}
	return true, nil
}

type UserModel struct {
	DB *sql.DB
}

func (m UserModel) Insert(user *User) error {
	query := `
			INSERT INTO users (login, password_hash, role, status, name)
			VALUES ($1,$2,$3,$4,$5)
			RETURNING id, created_at`
	args := []interface{}{user.Login, user.Password.hash, user.Role, user.Status, user.Name}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateLogin
		default:
			return err
		}
	}
	return nil
}

func (m UserModel) GetByLogin(email string) (*User, error) {
	query := `
		SELECT id, created_at, login, password_hash, name,status, role
		FROM users
		WHERE login = $1`
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := m.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Login,
		&user.Password.hash,
		&user.Name,
		&user.Status,
		&user.Role,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &user, nil
}
func (m UserModel) GetByID(ID int64) (*User, error) {
	query := `
		SELECT id, created_at, login, password_hash, name,status, role
		FROM users
		WHERE id = $1`
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := m.DB.QueryRowContext(ctx, query, ID).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Login,
		&user.Password.hash,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &user, nil
}

func (m UserModel) GetForToken(tokenScope, tokenPlaintext string) (*User, error) {

	tokenHash := sha256.Sum256([]byte(tokenPlaintext))

	query := `
		SELECT users.id, users.created_at, users.email, users.password_hash
		FROM users
		INNER JOIN tokens
		ON users.id = tokens.user_id
		WHERE tokens.hash = $1
		AND tokens.scope = $2
		AND tokens.expiry > $3`

	args := []interface{}{tokenHash[:], tokenScope, time.Now()}
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := m.DB.QueryRowContext(ctx, query, args...).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Login,
		&user.Password.hash,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &user, nil
}
