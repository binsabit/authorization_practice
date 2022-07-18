package api

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	router := httprouter.New()

	router.HandlerFunc(http.MethodGet, "/", app.IsAuthorized(app.Index))
	router.HandlerFunc(http.MethodPost, "/register", app.RegisterUser)
	router.HandlerFunc(http.MethodPost, "/login", app.LoginUser)

	return router
}
