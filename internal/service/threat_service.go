package service

import (
	"context"
	"strings"
	"threat-exchange/internal/dto"
	"threat-exchange/internal/repository"
	"time"
)

type ThreatService struct {
	repo repository.ThreatRepository
}

func NewThreatService(repo repository.ThreatRepository) *ThreatService {
	return &ThreatService{repo: repo}
}

func (s *ThreatService) Create(ctx context.Context, req *dto.ThreatCreateRequest) (*dto.ThreatResponse, error) {
	threat := req.ToModel()

	threat.Normalize()
	if err := threat.Validate(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	threat.CreatedAt = now
	threat.UpdatedAt = now

	if err := s.repo.Create(ctx, threat); err != nil {
		return nil, err
	}

	return dto.ToThreatResponse(threat), nil
}

func (s *ThreatService) GetByMD5(ctx context.Context, md5 string) (*dto.ThreatResponse, error) {
	md5 = strings.ToLower(md5)

	threat, err := s.repo.GetByMD5(ctx, md5)
	if err != nil {
		return nil, err
	}
	return dto.ToThreatResponse(threat), nil
}

func (s *ThreatService) Update(ctx context.Context, md5 string, req *dto.ThreatUpdateRequest) (*dto.ThreatResponse, error) {
	threat, err := s.repo.GetByMD5(ctx, md5)
	if err != nil {
		return nil, err
	}

	req.ApplyTo(threat)

	threat.Normalize()
	if err := threat.Validate(); err != nil {
		return nil, err
	}
	threat.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, threat); err != nil {
		return nil, err
	}

	return dto.ToThreatResponse(threat), nil
}
