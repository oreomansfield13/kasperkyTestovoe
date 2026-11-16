package api

import (
	"encoding/json"
	"net/http"
	"threat-exchange/internal/dto"
	"threat-exchange/internal/model"
	"threat-exchange/internal/service"
	"threat-exchange/internal/validate"
)

type ThreatHandler struct {
	svc *service.ThreatService
	vld *validate.Validator
}

func NewThreatHandler(svc *service.ThreatService, v *validate.Validator) *ThreatHandler {
	return &ThreatHandler{svc: svc, vld: v}
}

func (h *ThreatHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req dto.ThreatCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, model.ErrInvalid) // logging?
		return
	}

	if err := h.vld.Struct(&req); err != nil {
		WriteValidationError(w, err)
		return
	}

	resp, err := h.svc.Create(r.Context(), &req)
	if err != nil {
		WriteError(w, err)
		return
	}

	WriteJSON(w, http.StatusCreated, resp)
}

func (h *ThreatHandler) GetByMD5(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	if !validate.IsValidMD5(md5) {
		WriteError(w, model.ErrInvalid)
		return
	}
	resp, err := h.svc.GetByMD5(r.Context(), md5)
	if err != nil {
		WriteError(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, resp)
}

func (h *ThreatHandler) Update(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")
	if !validate.IsValidMD5(md5) {
		WriteError(w, model.ErrInvalid)
		return
	}

	var req dto.ThreatUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, model.ErrInvalid)
		return
	}
	if err := h.vld.Struct(&req); err != nil {
		WriteValidationError(w, err)
		return
	}

	resp, err := h.svc.Update(r.Context(), md5, &req)
	if err != nil {
		WriteError(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, resp)
}
