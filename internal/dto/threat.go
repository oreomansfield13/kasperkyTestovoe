package dto

import (
	"threat-exchange/internal/model"
	"time"
)

type ThreatCreateRequest struct {
	MD5         string   `json:"md5" validate:"required,md5"`
	SHA256      string   `json:"sha256" validate:"omitempty,sha256"`
	Name        string   `json:"name" validate:"required,min=1,max=255"`
	ThreatType  string   `json:"type" validate:"required,threat_type"`
	Severity    string   `json:"severity" validate:"required,severity"`
	Description string   `json:"description" validate:"max=4000"`
	FileSize    int64    `json:"file_size" validate:"gte=0"`
	FileType    string   `json:"file_type" validate:"max=100"`
	Tags        []string `json:"tags" validate:"max=50,dive,max=50"`
	References  []string `json:"references" validate:"max=50,dive,url"`
}

type ThreatUpdateRequest struct {
	Name        string   `json:"name" validate:"required,min=1,max=255"`
	ThreatType  string   `json:"type" validate:"required,threat_type"`
	Severity    string   `json:"severity" validate:"required,severity"`
	Description string   `json:"description" validate:"max=4000"`
	FileSize    int64    `json:"file_size" validate:"gte=0"`
	FileType    string   `json:"file_type" validate:"max=100"`
	Tags        []string `json:"tags" validate:"max=50,dive,max=50"`
	References  []string `json:"references" validate:"max=50,dive,url"`
}

type ThreatResponse struct {
	MD5         string    `json:"md5"`
	SHA256      string    `json:"sha256"`
	Name        string    `json:"name"`
	ThreatType  string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	FileSize    int64     `json:"file_size"`
	FileType    string    `json:"file_type"`
	Tags        []string  `json:"tags"`
	References  []string  `json:"references"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (r *ThreatCreateRequest) ToModel() *model.Threat {
	return &model.Threat{
		MD5:         r.MD5,
		SHA256:      r.SHA256,
		Name:        r.Name,
		ThreatType:  model.ThreatType(r.ThreatType),
		Severity:    model.Severity(r.Severity),
		Description: r.Description,
		FileSize:    r.FileSize,
		FileType:    r.FileType,
		Tags:        r.Tags,
		References:  r.References,
	}
}

func (r *ThreatUpdateRequest) ApplyTo(t *model.Threat) {
	t.Name = r.Name
	t.ThreatType = model.ThreatType(r.ThreatType)
	t.Severity = model.Severity(r.Severity)
	t.Description = r.Description
	t.FileSize = r.FileSize
	t.FileType = r.FileType
	t.Tags = r.Tags
	t.References = r.References
}

func ToThreatResponse(t *model.Threat) *ThreatResponse {
	return &ThreatResponse{
		MD5:         t.MD5,
		SHA256:      t.SHA256,
		Name:        t.Name,
		ThreatType:  string(t.ThreatType),
		Severity:    string(t.Severity),
		Description: t.Description,
		FileSize:    t.FileSize,
		FileType:    t.FileType,
		Tags:        t.Tags,
		References:  t.References,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}
