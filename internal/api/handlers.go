package api

import (
	"errors"
	"net/http"
	"time"

	data "github.com/binsabit/authorization_practice/internal/data/models"
	"github.com/binsabit/authorization_practice/internal/data/validator"
	"github.com/binsabit/authorization_practice/internal/helpers"
	"github.com/julienschmidt/httprouter"
)

func (app *application) Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

}

func (app *application) RegisterUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	app.logger.Println("Registering user")

	var input struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		Status   string `json:"status"`
		Role     string `json:"role"`
		Name     string `json:"name"`
	}

	err := helpers.ReadJSON(w, r, &input)
	if err != nil {
		helpers.BadRequestResponse(w, r, err)
		return
	}

	user := &data.User{
		Login:  input.Login,
		Name:   input.Name,
		Status: input.Status,
		Role:   input.Role,
	}

	err = user.Password.Set(input.Password)
	if err != nil {
		helpers.ServerErrorResponse(w, r, err)
		return
	}
	v := validator.New()

	if data.ValidateUser(v, user); !v.Valid() {
		helpers.FailedValidationResponse(w, r, v.Errors)
	}
	err = app.models.Users.Insert(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateLogin):
			helpers.BadRequestResponse(w, r, err)
			// app.failedValidationResponse(w, r, v.Errors)
		default:
			helpers.ServerErrorResponse(w, r, err)
		}
		return
	}

	err = helpers.WriteJSON(w, http.StatusCreated, helpers.Envelope{"user": user}, nil)
	if err != nil {
		helpers.ServerErrorResponse(w, r, err)
	}

}

func (app *application) LoginUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	app.logger.Println("Signing in user")

	var input struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	err := helpers.ReadJSON(w, r, &input)
	if err != nil {
		helpers.BadRequestResponse(w, r, err)
		return
	}

	v := validator.New()
	data.ValidateLogin(v, input.Login)
	data.ValidatePasswordPlaintext(v, input.Password)

	if !v.Valid() {
		helpers.FailedValidationResponse(w, r, v.Errors)
	}

	user, err := app.models.Users.GetByLogin(input.Login)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			helpers.InvalidCredentialsResponse(w, r)
			return
		default:
			helpers.ServerErrorResponse(w, r, err)
		}
		return
	}

	matched, err := user.Password.Matches(input.Password)
	if err != nil {
		helpers.InvalidCredentialsResponse(w, r)
		return
	}

	if !matched {
		helpers.InvalidCredentialsResponse(w, r)
		return
	}

	accesssToken, err := app.models.Tokens.NewToken(*user, data.TypeAccess, time.Minute*15)
	if err != nil {
		helpers.ServerErrorResponse(w, r, err)
		return
	}
	err = helpers.WriteJSON(w, http.StatusCreated, helpers.Envelope{"authentication": accesssToken}, nil)
}
