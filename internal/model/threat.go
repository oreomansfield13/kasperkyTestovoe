package model

import (
	"errors"
	"fmt"
	"strings"
	"threat-exchange/internal/validate"
	"time"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type ThreatType string

const (
	TypeMalware ThreatType = "malware"
	TypeTrojan  ThreatType = "trojan"
	TypeRansom  ThreatType = "ransomware"
	TypeFishing ThreatType = "fishing"
)

type Threat struct {
	MD5         string
	Name        string
	SHA256      string
	ThreatType  ThreatType
	Severity    Severity
	Description string
	FileSize    int64
	FileType    string
	Tags        []string
	References  []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
	ErrInvalid  = errors.New("invalid threat data")
)

func (t *Threat) Normalize() {
	t.MD5 = strings.ToLower(strings.TrimSpace(t.MD5))
	t.SHA256 = strings.ToLower(strings.TrimSpace(t.SHA256))
	t.Name = strings.TrimSpace(t.Name)
	t.Description = strings.TrimSpace(t.Description)
	t.FileType = strings.TrimSpace(t.FileType)

	clean := make([]string, 0, len(t.Tags))
	seen := make(map[string]bool, len(t.Tags))
	for _, tag := range t.Tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		clean = append(clean, tag)
	}
	t.Tags = clean

	if t.References == nil {
		t.References = make([]string, 0)
	}
}

func (t *Threat) Validate() error {
	if !validate.IsValidMD5(t.MD5) {
		return fmt.Errorf("%w: md5 must be 32 hex characters", ErrInvalid)
	}
	if t.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if !validate.IsValidSHA256(t.SHA256) {
		return fmt.Errorf("%w: SHA256 must be 64 hex characters or empty", ErrInvalid)
	}
	if !validate.IsValidSeverity(string(t.Severity)) {
		return fmt.Errorf("%w: invalid severity '%s'", ErrInvalid, t.Severity)
	}
	if !validate.IsValidThreatType(string(t.ThreatType)) {
		return fmt.Errorf("%w: invalid threat type '%s'", ErrInvalid, t.ThreatType)
	}
	if t.FileSize < 0 {
		return fmt.Errorf("%w: file_size cannot be negative", ErrInvalid)
	}
	for _, ref := range t.References {
		if !validate.IsValidURL(ref) {
			return fmt.Errorf("%w: invalid reference url '%s'", ErrInvalid, ref)
		}
	}
	return nil
}
