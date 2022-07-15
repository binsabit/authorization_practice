package api

import "github.com/julienschmidt/httprouter"

func (app *application) routes() *httprouter.Router {
	router := httprouter.New()

	router.GET("/", app.Index)
	router.POST("/register", app.RegisterUser)
	router.POST("/login", app.LoginUser)
	return router
}
