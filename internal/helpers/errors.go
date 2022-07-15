package helpers

import (
	"fmt"
	"log"
	"net/http"
)

func logError(r *http.Request, err error) {
	log.Println(err)
}

func errorResponse(w http.ResponseWriter, r *http.Request, status int, message interface{}) {
	env := Envelope{"error": message}

	err := WriteJSON(w, status, env, nil)
	if err != nil {
		logError(r, err)
		w.WriteHeader(500)
	}
}

func ServerErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	logError(r, err)
	message := "the server encounterd a problem and could not process your request"
	errorResponse(w, r, http.StatusInternalServerError, message)
}

func NotFoundResponse(w http.ResponseWriter, r *http.Request) {
	message := "the request recource could not be found"
	errorResponse(w, r, http.StatusNotFound, message)
}

func MethodNotAllowedResponse(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf("the %s method is not supported for this resource", r.Method)
	errorResponse(w, r, http.StatusMethodNotAllowed, message)
}

func BadRequestResponse(w http.ResponseWriter, r *http.Request, err error) {
	errorResponse(w, r, http.StatusBadRequest, err.Error())
}

func FailedValidationResponse(w http.ResponseWriter, r *http.Request, errors map[string]string) {
	errorResponse(w, r, http.StatusUnprocessableEntity, errors)
}

func InvalidCredentialsResponse(w http.ResponseWriter, r *http.Request) {
	message := "invalid authentication credentials"
	errorResponse(w, r, http.StatusUnauthorized, message)
}

func InvalidAuthenticationTokenResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	message := "invalid or missing authentication token"
	errorResponse(w, r, http.StatusUnauthorized, message)
}

func AuthenticationRequiredResponse(w http.ResponseWriter, r *http.Request) {
	message := "you must be authenticated to access this resource"
	errorResponse(w, r, http.StatusUnauthorized, message)
}
