package repository

import (
	"context"
	"sync"
	"threat-exchange/internal/model"
)

type memoryRepo struct {
	mu      sync.RWMutex
	threats map[string]*model.Threat
}

func NewMemoryRepository() ThreatRepository {
	return &memoryRepo{
		threats: make(map[string]*model.Threat),
	}
}

func cloneThreat(t *model.Threat) *model.Threat {
	if t == nil {
		return nil
	}
	threatCopy := *t
	threatCopy.Tags = append([]string{}, t.Tags...)
	threatCopy.References = append([]string{}, t.References...)
	return &threatCopy
}

func (r *memoryRepo) Create(ctx context.Context, threat *model.Threat) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.threats[threat.MD5]; exists {
		return model.ErrConflict
	}

	r.threats[threat.MD5] = cloneThreat(threat)
	return nil
}

func (r *memoryRepo) GetByMD5(ctx context.Context, md5 string) (*model.Threat, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	threat, exists := r.threats[md5]
	if !exists {
		return nil, model.ErrNotFound
	}

	return cloneThreat(threat), nil
}

func (r *memoryRepo) Update(ctx context.Context, threat *model.Threat) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.threats[threat.MD5]; !exists {
		return model.ErrNotFound
	}
	r.threats[threat.MD5] = cloneThreat(threat)
	return nil
}
