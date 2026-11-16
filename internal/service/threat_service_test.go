package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/dto"
	"threat-exchange/internal/model"
	"threat-exchange/internal/repository"
	"threat-exchange/internal/service"
)

func setupService() *service.ThreatService {
	repo := repository.NewMemoryRepository()
	return service.NewThreatService(repo)
}

func validCreateRequest() *dto.ThreatCreateRequest {
	return &dto.ThreatCreateRequest{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Trojan.Win32.Generic",
		ThreatType:  "trojan",
		Severity:    "high",
		Description: "Test description",
		FileSize:    1024,
		FileType:    "exe",
		Tags:        []string{"test", "trojan"},
		References:  []string{"https://example.com"},
	}
}

func TestThreatService_Create_Success(t *testing.T) {
	svc := setupService()
	ctx := context.Background()
	req := validCreateRequest()

	resp, err := svc.Create(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, req.MD5, resp.MD5)
	assert.Equal(t, req.Name, resp.Name)
	assert.Equal(t, req.Severity, resp.Severity)
	assert.False(t, resp.CreatedAt.IsZero())
	assert.False(t, resp.UpdatedAt.IsZero())
}

func TestThreatService_Create_Conflict(t *testing.T) {
	svc := setupService()
	ctx := context.Background()
	req := validCreateRequest()

	_, err := svc.Create(ctx, req)
	require.NoError(t, err)

	_, err = svc.Create(ctx, req)

	require.Error(t, err)
	assert.ErrorIs(t, err, model.ErrConflict)
}

func TestThreatService_Create_Invalid(t *testing.T) {
	svc := setupService()
	ctx := context.Background()

	req1 := validCreateRequest()
	req1.MD5 = "short_md5"
	_, err := svc.Create(ctx, req1)
	assert.ErrorIs(t, err, model.ErrInvalid, "должен отловить невалидный MD5")

	req2 := validCreateRequest()
	req2.Severity = "super_high"
	_, err = svc.Create(ctx, req2)
	assert.ErrorIs(t, err, model.ErrInvalid, "должен отловить невалидный severity")
}

func TestThreatService_GetByMD5_Success(t *testing.T) {
	svc := setupService()
	ctx := context.Background()
	req := validCreateRequest()

	_, err := svc.Create(ctx, req)
	require.NoError(t, err)

	resp, err := svc.GetByMD5(ctx, req.MD5)

	require.NoError(t, err)
	assert.Equal(t, req.Name, resp.Name)
}

func TestThreatService_GetByMD5_CaseInsensitive(t *testing.T) {
	svc := setupService()
	ctx := context.Background()
	req := validCreateRequest()

	_, err := svc.Create(ctx, req)
	require.NoError(t, err)

	upperMD5 := "D41D8CD98F00B204E9800998ECF8427E"
	resp, err := svc.GetByMD5(ctx, upperMD5)

	require.NoError(t, err, "должен найти, даже если регистр отличается")
	assert.NotNil(t, resp)
}

func TestThreatService_GetByMD5_NotFound(t *testing.T) {
	svc := setupService()
	ctx := context.Background()

	_, err := svc.GetByMD5(ctx, "00000000000000000000000000000000")

	require.Error(t, err)
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func TestThreatService_Update_Success(t *testing.T) {
	svc := setupService()
	ctx := context.Background()
	reqCreate := validCreateRequest()

	created, err := svc.Create(ctx, reqCreate)
	require.NoError(t, err)

	reqUpdate := &dto.ThreatUpdateRequest{
		Name:        "Trojan.Win32.Updated",
		ThreatType:  "ransomware",
		Severity:    "critical",
		Description: "Updated description",
		FileSize:    2048,
		FileType:    "dll",
		Tags:        []string{"updated"},
		References:  []string{"https://updated.com"},
	}

	updated, err := svc.Update(ctx, created.MD5, reqUpdate)
	require.NoError(t, err)

	assert.Equal(t, reqUpdate.Name, updated.Name)
	assert.Equal(t, reqUpdate.Severity, updated.Severity)
	assert.Equal(t, reqUpdate.FileSize, updated.FileSize)
	assert.True(t, updated.UpdatedAt.After(created.CreatedAt), "Время Update должно быть позже Create")
}

func TestThreatService_Update_NotFound(t *testing.T) {
	svc := setupService()
	ctx := context.Background()

	reqUpdate := &dto.ThreatUpdateRequest{
		Name:       "Updated",
		ThreatType: "trojan",
		Severity:   "high",
	}

	_, err := svc.Update(ctx, "00000000000000000000000000000000", reqUpdate)
	require.Error(t, err)
	assert.ErrorIs(t, err, model.ErrNotFound)
}
