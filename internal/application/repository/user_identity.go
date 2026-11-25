package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
)

// ErrUserIdentityExists is returned when a (provider, provider_subject) pair is
// already bound to some local user. The SSO service treats it as "another
// concurrent login won the race" and re-reads the winner rather than failing
// the request outright.
var ErrUserIdentityExists = errors.New("external identity is already bound")

type userIdentityRepository struct {
	db *gorm.DB
}

// NewUserIdentityRepository creates a repository backed by GORM.
func NewUserIdentityRepository(db *gorm.DB) interfaces.UserIdentityRepository {
	return &userIdentityRepository{db: db}
}

func (r *userIdentityRepository) first(q *gorm.DB) (*types.UserIdentity, error) {
	var identity types.UserIdentity
	err := q.First(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user identity: %w", err)
	}
	return &identity, nil
}

func (r *userIdentityRepository) FindByProviderSubject(
	ctx context.Context, provider, providerSubject string,
) (*types.UserIdentity, error) {
	provider = strings.TrimSpace(provider)
	providerSubject = strings.TrimSpace(providerSubject)
	if provider == "" || providerSubject == "" {
		return nil, nil
	}
	return r.first(r.db.WithContext(ctx).
		Where("provider = ? AND provider_subject = ?", provider, providerSubject))
}

func (r *userIdentityRepository) FindByUserAndProvider(
	ctx context.Context, userID, provider string,
) (*types.UserIdentity, error) {
	userID = strings.TrimSpace(userID)
	provider = strings.TrimSpace(provider)
	if userID == "" || provider == "" {
		return nil, nil
	}
	return r.first(r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider))
}

func (r *userIdentityRepository) Create(ctx context.Context, identity *types.UserIdentity) error {
	if identity == nil || identity.ID == "" || identity.UserID == "" ||
		identity.Provider == "" || identity.ProviderSubject == "" {
		return errors.New("user identity requires id, user_id, provider and provider_subject")
	}
	if err := r.db.WithContext(ctx).Create(identity).Error; err != nil {
		if isUserIdentityUniqueViolation(err) {
			return ErrUserIdentityExists
		}
		return fmt.Errorf("create user identity: %w", err)
	}
	return nil
}

func (r *userIdentityRepository) Update(ctx context.Context, identity *types.UserIdentity) error {
	if identity == nil || identity.ID == "" {
		return errors.New("user identity id is required")
	}
	if err := r.db.WithContext(ctx).Save(identity).Error; err != nil {
		return fmt.Errorf("update user identity: %w", err)
	}
	return nil
}

func (r *userIdentityRepository) DeleteByUserID(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&types.UserIdentity{}).Error; err != nil {
		return fmt.Errorf("delete user identities for user %s: %w", userID, err)
	}
	return nil
}

// isUserIdentityUniqueViolation reports whether err is a duplicate-key failure
// on either unique index of user_identities. It matches on message wording
// because the two supported drivers (pgx, mattn/go-sqlite3) do not expose a
// shared sentinel error, and gorm wraps driver errors.
func isUserIdentityUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "unique") && !strings.Contains(msg, "duplicate") {
		return false
	}
	// Scope the match to this table so a duplicate from an unrelated insert
	// inside a shared transaction is not misreported as an identity conflict.
	return strings.Contains(msg, "user_identities") ||
		strings.Contains(msg, "provider") ||
		strings.Contains(msg, "user_id")
}
