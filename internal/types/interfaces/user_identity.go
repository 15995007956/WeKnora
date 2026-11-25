package interfaces

import (
	"context"

	"github.com/Tencent/WeKnora/internal/types"
)

// UserIdentityRepository persists bindings between local users and external
// login identities (DingTalk unionId today).
//
// The SSO login flow only needs three operations: resolve an incoming external
// identity to a local user, bind one that was just provisioned, and refresh the
// cached profile on every login. Anything else (unlinking, listing) is left out
// deliberately so the surface stays small and auditable.
type UserIdentityRepository interface {
	// FindByProviderSubject resolves an external identity to its binding.
	// It returns (nil, nil) when nothing is bound, so callers can distinguish
	// "not linked yet" from a real database error.
	FindByProviderSubject(
		ctx context.Context, provider, providerSubject string,
	) (*types.UserIdentity, error)

	// FindByUserAndProvider returns the binding of one local user for one
	// provider, used to render "this account is linked to X" in the profile.
	// It returns (nil, nil) when the user has no binding for that provider.
	FindByUserAndProvider(
		ctx context.Context, userID, provider string,
	) (*types.UserIdentity, error)

	// Create stores a new binding. It must fail (rather than silently
	// replacing) when the (provider, provider_subject) pair is already bound,
	// so two concurrent first-time logins cannot create two local accounts.
	Create(ctx context.Context, identity *types.UserIdentity) error

	// Update refreshes the cached profile and last-login timestamp.
	Update(ctx context.Context, identity *types.UserIdentity) error

	// DeleteByUserID removes every binding of a local user. Used when an
	// account is deleted so a re-created identity does not point at a
	// nonexistent user row.
	DeleteByUserID(ctx context.Context, userID string) error
}
