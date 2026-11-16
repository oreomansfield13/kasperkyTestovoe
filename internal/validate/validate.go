package validate

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var (
	md5Regex    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

var (
	validSeverities  = []string{"low", "medium", "high", "critical"}
	validThreatTypes = []string{"malware", "trojan", "ransomware", "fishing"}
)

func IsValidMD5(s string) bool {
	return md5Regex.MatchString(s)
}

func IsValidSHA256(s string) bool {
	return s == "" || sha256Regex.MatchString(s)
}

func IsValidURL(s string) bool {
	u, err := url.ParseRequestURI(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func IsValidSeverity(s string) bool {
	for _, v := range validSeverities {
		if s == v {
			return true
		}
	}
	return false
}

func IsValidThreatType(s string) bool {
	for _, v := range validThreatTypes {
		if s == v {
			return true
		}
	}
	return false
}

type Validator struct {
	v *validator.Validate
}

func New() *Validator {
	v := validator.New(validator.WithRequiredStructEnabled())

	_ = v.RegisterValidation("md5", func(fl validator.FieldLevel) bool {
		return IsValidMD5(fl.Field().String())
	})

	_ = v.RegisterValidation("sha256", func(fl validator.FieldLevel) bool {
		return IsValidSHA256(fl.Field().String())
	})

	_ = v.RegisterValidation("url", func(fl validator.FieldLevel) bool {
		return IsValidURL(fl.Field().String())
	})

	_ = v.RegisterValidation("severity", func(fl validator.FieldLevel) bool {
		return IsValidSeverity(fl.Field().String())
	})

	_ = v.RegisterValidation("threat_type", func(fl validator.FieldLevel) bool {
		return IsValidThreatType(fl.Field().String())
	})

	return &Validator{v: v}
}

func (vl *Validator) Struct(s interface{}) error {
	if err := vl.v.Struct(s); err != nil {
		if errs, ok := err.(validator.ValidationErrors); ok {
			return formatErrors(errs)
		}
		return err
	}
	return nil
}

func formatErrors(errs validator.ValidationErrors) error {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		switch e.Tag() {
		case "required":
			msgs = append(msgs, fmt.Sprintf("%s is required", e.Field()))
		case "min":
			msgs = append(msgs, fmt.Sprintf("%s must be at least %s", e.Field(), e.Param()))
		case "max":
			msgs = append(msgs, fmt.Sprintf("%s must be at most %s", e.Field(), e.Param()))
		case "gte":
			msgs = append(msgs, fmt.Sprintf("%s must be >= %s", e.Field(), e.Param()))
		case "md5":
			msgs = append(msgs, fmt.Sprintf("%s must be a valid MD5 hash (32 hex chars)", e.Field()))
		case "sha256":
			msgs = append(msgs, fmt.Sprintf("%s must be a valid SHA256 hash (64 hex chars)", e.Field()))
		case "url":
			msgs = append(msgs, fmt.Sprintf("%s must be a valid URL", e.Field()))
		case "severity":
			msgs = append(msgs, fmt.Sprintf("%s must be one of: %s", e.Field(), strings.Join(validSeverities, ", ")))
		case "threat_type":
			msgs = append(msgs, fmt.Sprintf("%s must be one of: %s", e.Field(), strings.Join(validThreatTypes, ", ")))
		default:
			msgs = append(msgs, fmt.Sprintf("%s failed on '%s'", e.Field(), e.Tag()))
		}
	}
	return fmt.Errorf("validation error: %s", strings.Join(msgs, "; "))
}
