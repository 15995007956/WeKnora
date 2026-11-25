package types

import (
	"time"

	"gorm.io/gorm"
)

// External identity providers supported by the single-sign-on login flows.
// The value is persisted in user_identities.provider, so it must stay stable.
const (
	// IdentityProviderDingTalk is DingTalk (钉钉) QR-code / SSO login.
	IdentityProviderDingTalk = "dingtalk"
)

// UserIdentity binds a local user account to one external login identity.
//
// Why a separate table instead of columns on users: users already carries two
// unique indexes (username, email), and an external subject is a different
// kind of key. Keeping bindings in their own table lets one local account hold
// several providers (DingTalk today, WeCom/Feishu later) and lets a local
// account be deactivated without losing the historical binding.
//
// Lookup key: (Provider, ProviderSubject). For DingTalk the subject is the
// unionId — stable for a given user within an organization, and the only
// identifier the contact API reliably returns (corpId-scoped email is absent
// for many enterprise applications).
type UserIdentity struct {
	// ID is the row identifier (UUID).
	ID string `json:"id" gorm:"type:varchar(36);primaryKey"`
	// UserID points at the local users.id this identity authenticates as.
	UserID string `json:"user_id" gorm:"type:varchar(36);not null;uniqueIndex:uq_user_identities_user_provider,priority:1"`
	// Provider is one of the IdentityProvider* constants.
	Provider string `json:"provider" gorm:"type:varchar(32);not null;uniqueIndex:uq_user_identities_provider_subject,priority:1;uniqueIndex:uq_user_identities_user_provider,priority:2"`
	// ProviderSubject is the provider-side stable identifier (DingTalk unionId).
	ProviderSubject string `json:"provider_subject" gorm:"type:varchar(128);not null;uniqueIndex:uq_user_identities_provider_subject,priority:2"`
	// ProviderTenant optionally scopes the binding to a provider-side
	// organization (DingTalk corpId). Empty means "not scoped".
	ProviderTenant string `json:"provider_tenant,omitempty" gorm:"type:varchar(64)"`
	// DisplayName and AvatarURL cache the provider profile so the UI can show
	// a sensible name before the user edits their local profile.
	DisplayName string `json:"display_name,omitempty" gorm:"type:varchar(255)"`
	AvatarURL   string `json:"avatar_url,omitempty"   gorm:"type:varchar(500)"`
	// LastLoginAt records the most recent successful SSO login through this
	// binding; nil until the first login after binding.
	LastLoginAt *time.Time     `json:"last_login_at,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
}

// TableName pins the table name so renames of the Go type cannot silently
// break the migration-managed schema.
func (UserIdentity) TableName() string {
	return "user_identities"
}
