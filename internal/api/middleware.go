package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	data "github.com/binsabit/authorization_practice/internal/data/models"
	"github.com/binsabit/authorization_practice/internal/data/validator"
	"github.com/binsabit/authorization_practice/internal/helpers"
	"github.com/golang-jwt/jwt"
)

func (app *application) IsAuthorizedJWT(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Add("Vary", "Authorization")
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			r = app.contextSetUser(r, data.AnonymousUser)
			next.ServeHTTP(w, r)
			return
		}

		mySigningKey := []byte(data.Secretkey)

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			helpers.InvalidAuthenticationTokenResponse(w, r)
			return
		}

		rawToken := headerParts[1]
		v := validator.New()

		if data.ValidateTokenPlaintext(v, rawToken); !v.Valid() {
			helpers.InvalidAuthenticationTokenResponse(w, r)
			return
		}

		token, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
			return mySigningKey, nil
		})

		if err != nil {
			helpers.InvalidAuthenticationTokenResponse(w, r)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			userIDStr := fmt.Sprintf("%v", claims["user_id"])
			userIDInt, _ := strconv.ParseInt(userIDStr, 10, 64)
			user, err := app.models.Users.GetByID(userIDInt)
			if err != nil {
				helpers.ServerErrorResponse(w, r, err)
			}
			r = app.contextSetUser(r, user)
			next.ServeHTTP(w, r)
		}

	})
}

func (app *application) CheckRefresh(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Add("Vary", "Authorization")
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			r = app.contextSetUser(r, data.AnonymousUser)
			next.ServeHTTP(w, r)
			return
		}

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			helpers.InvalidAuthenticationTokenResponse(w, r)
			return
		}

		rawToken := headerParts[1]
		v := validator.New()

		if data.ValidateTokenPlaintext(v, rawToken); !v.Valid() {
			helpers.InvalidAuthenticationTokenResponse(w, r)
			return
		}

		user, err := app.models.Users.GetForToken(data.TypeRefresh, rawToken)
		if err != nil {
			switch {
			case errors.Is(err, data.ErrRecordNotFound):
				helpers.InvalidAuthenticationTokenResponse(w, r)
			default:
				helpers.ServerErrorResponse(w, r, err)
			}
			return
		}

		r = app.contextSetUser(r, user)
		next.ServeHTTP(w, r)

	})
}
