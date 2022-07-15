package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

type Envelope map[string]interface{}

func ReadJSON(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	maxBytes := 1_048_576
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err != nil {
		log.Println("here")
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		var invalidUnmarshalError *json.InvalidUnmarshalError

		switch {
		case errors.As(err, &syntaxError):
			return fmt.Errorf("body contains badly formed JSON (at character %d)", syntaxError.Offset)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return errors.New("body contains basly formed JSON")
		case errors.As(err, &unmarshalTypeError):
			if unmarshalTypeError.Field != "" {
				return fmt.Errorf("body contains incorrect JSON type for field %q", unmarshalTypeError.Field)
			}
			return fmt.Errorf("body contains incorrect JSON type (at character $d)", unmarshalTypeError.Offset)
		case strings.HasPrefix(err.Error(), "json:unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			return fmt.Errorf("body contains unknowns key %s", fieldName)
		case err.Error() == "http: request body too large":
			// return fmt.Errorf("body must not be larger than %d bytes", maxBytes)
		case errors.Is(err, io.EOF):
			return errors.New("body must not be empty")
		case errors.As(err, &invalidUnmarshalError):
			panic(err)
		default:
			return err

		}

	}
	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		return errors.New("body must only contain single JSON value")
	}

	return nil
}

func WriteJSON(w http.ResponseWriter, status int, data Envelope, headers http.Header) error {
	js, err := json.Marshal(data)
	if err != nil {
		return err
	}

	for key, val := range headers {
		w.Header()[key] = val
	}
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")

	// w.WriteHeader(status)
	w.Write(js)
	return nil
}
