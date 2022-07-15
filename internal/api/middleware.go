package api

import (
	"fmt"
	"net/http"
	"strings"

	data "github.com/binsabit/authorization_practice/internal/data/models"
	"github.com/binsabit/authorization_practice/internal/helpers"
	"github.com/golang-jwt/jwt"
)

func IsAuthorized(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Authorization")
		authorizationHeader := r.Header.Get("Authorization")

		if authorizationHeader == "" {
			r = contextSetUser(r, data.AnonymousUser)
			next.ServeHTTP(w, r)
			return
		}

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			helpers.InvalidAuthenticationTokenResponse(w, r)
			return
		}

		rawtoken := headerParts[1]
		var mySigningKey = []byte(data.Secretkey)

		token, err := jwt.Parse(rawtoken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing")
			}
			return mySigningKey, nil
		})

	})
}
