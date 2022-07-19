package api

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	router := httprouter.New()

	router.HandlerFunc(http.MethodGet, "/", app.IsAuthorizedJWT(app.Index))
	router.HandlerFunc(http.MethodPost, "/auth/register", app.RegisterUser)
	router.HandlerFunc(http.MethodPost, "/auth/login", app.LoginUser)
	router.HandlerFunc(http.MethodGet, "/auth/logout", app.IsAuthorizedJWT(app.LogoutUser))
	router.HandlerFunc(http.MethodGet, "/auth/refresh", app.CheckRefresh(app.RefreshSession))

	return router
}
