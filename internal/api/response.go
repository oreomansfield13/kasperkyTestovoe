package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"threat-exchange/internal/dto"
	"threat-exchange/internal/model"
)

func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

func WriteError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	msg := "Internal Server Error"
	details := err.Error()

	if errors.Is(err, model.ErrNotFound) {
		status = http.StatusNotFound
		msg = "Threat not found"
	} else if errors.Is(err, model.ErrConflict) {
		status = http.StatusConflict
		msg = "Threat already exists"
	} else if errors.Is(err, model.ErrInvalid) {
		status = http.StatusBadRequest
		msg = "Invalid request data"
	}

	WriteJSON(w, status, dto.ErrorResponse{
		Message: msg,
		Details: details,
	})
}

func WriteValidationError(w http.ResponseWriter, err error) {
	WriteJSON(w, http.StatusBadRequest, dto.ErrorResponse{
		Message: "Validation error",
		Details: err.Error(),
	})
}
