package repository

import (
	"context"
	"threat-exchange/internal/model"
)

type ThreatRepository interface {
	Create(ctx context.Context, threat *model.Threat) error
	GetByMD5(ctx context.Context, md5 string) (*model.Threat, error)
	Update(ctx context.Context, threat *model.Threat) error
}
