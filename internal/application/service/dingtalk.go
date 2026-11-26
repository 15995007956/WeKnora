package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	apprepo "github.com/Tencent/WeKnora/internal/application/repository"
	"github.com/Tencent/WeKnora/internal/config"
	"github.com/Tencent/WeKnora/internal/logger"
	"github.com/Tencent/WeKnora/internal/types"
	secutils "github.com/Tencent/WeKnora/internal/utils"
)

var (
	// ErrDingTalkDisabled is returned when the DingTalk login flow is called
	// while the feature is switched off or its credentials are incomplete.
	ErrDingTalkDisabled = errors.New("DingTalk login is disabled")

	// ErrDingTalkUnknownIdentity is returned in strict allow-list mode
	// (provisioning_mode=deny) when the scanned unionId has no local account
	// bound to it. Handlers map it to a "contact an administrator" message
	// instead of a generic failure, so the user knows what to do.
	ErrDingTalkUnknownIdentity = errors.New(
		"this DingTalk account is not linked to a WeKnora user; ask an administrator to grant access",
	)

	// ErrDingTalkUserInactive mirrors the account-disabled rejection both the
	// password and OIDC login paths apply.
	ErrDingTalkUserInactive = errors.New("account is disabled")

	// ErrDingTalkAccountAlreadyClaimed is returned when the nickname matches a
	// pre-created account that a different DingTalk unionId already owns. The
	// message tells the user to ask an administrator, since the resolution
	// (free the old binding, or pick a different nickname) is theirs.
	ErrDingTalkAccountAlreadyClaimed = errors.New(
		"this nickname is already bound to another DingTalk account; " +
			"ask an administrator to reset the binding",
	)
)

// dingTalkTokenResponse is the body returned by DingTalk's userAccessToken
// endpoint. Only the fields the flow needs are modelled.
type dingTalkTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireIn    int64  `json:"expireIn"`
	CorpID      string `json:"corpId"`
}

// dingTalkUserInfo is the subset of DingTalk's /contact/users/me response the
// login flow consumes. UnionID is the stable identifier used as the binding
// subject; nick/avatar are cached for display only.
type dingTalkUserInfo struct {
	Nick      string `json:"nick"`
	UnionID   string `json:"unionId"`
	OpenID    string `json:"openId"`
	AvatarURL string `json:"avatarUrl"`
	Mobile    string `json:"mobile"`
	Email     string `json:"email"`
	StateCode string `json:"stateCode"`
}

// dingTalkErrorBody captures DingTalk's error envelope so failures can be
// logged with the provider's own code instead of an opaque HTTP status.
type dingTalkErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestid"`
}

// dingTalkHTTPClient mirrors the OIDC client: SSRF-safe and time bounded, so a
// blocked or slow provider cannot hang a login request.
func newDingTalkHTTPClient() *http.Client {
	cfg := secutils.DefaultSSRFSafeHTTPClientConfig()
	cfg.Timeout = 30 * time.Second
	return secutils.NewSSRFSafeHTTPClient(cfg)
}

// dingTalkConfig returns the effective configuration, or ErrDingTalkDisabled
// when the feature is off.
//
// The behavioural switches (enable, password login, allow-list, provisioning
// mode) are resolved through SystemSettingService on every call, so an
// administrator editing them under Settings → System does not need a restart
// and the DB value overrides the environment. Credentials and endpoints stay
// startup-bound: they are secrets and operator-supplied URLs, and exposing them
// through the settings API would leak the secret to any system administrator
// session.
func (s *userService) dingTalkConfig(ctx context.Context) (*config.DingTalkAuthConfig, error) {
	if s.config == nil || s.config.DingTalkAuth == nil {
		return nil, ErrDingTalkDisabled
	}
	// Copy so the runtime overrides below never mutate shared startup state.
	cfg := *s.config.DingTalkAuth

	if s.systemSettingSvc != nil {
		cfg.Enable = s.systemSettingSvc.GetBool(
			ctx, "auth.dingtalk_enabled", "DINGTALK_AUTH_ENABLE", cfg.Enable,
		)
		passwordLogin := s.systemSettingSvc.GetBool(
			ctx, "auth.dingtalk_password_login_enabled",
			"DINGTALK_PASSWORD_LOGIN_ENABLED", cfg.PasswordLoginAllowed(),
		)
		cfg.PasswordLoginEnabled = &passwordLogin
		cfg.BindByEmail = s.systemSettingSvc.GetBool(
			ctx, "auth.dingtalk_allowlist_enabled", "DINGTALK_BIND_BY_EMAIL", cfg.BindByEmail,
		)
		cfg.ProvisioningMode = s.systemSettingSvc.GetString(
			ctx, "auth.dingtalk_provisioning_mode",
			"DINGTALK_PROVISIONING_MODE", cfg.ProvisioningMode,
		)
	}

	if !cfg.Enabled() {
		return nil, ErrDingTalkDisabled
	}
	if err := validateDingTalkEndpoints(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// effectivePasswordLoginAllowed reports whether the email/password form should
// be offered, honouring the runtime override when the settings service is wired.
func (s *userService) effectivePasswordLoginAllowed(ctx context.Context) bool {
	if s.systemSettingSvc == nil || s.config == nil || s.config.DingTalkAuth == nil {
		return s.config == nil || s.config.DingTalkAuth.PasswordLoginAllowed()
	}
	return s.systemSettingSvc.GetBool(
		ctx, "auth.dingtalk_password_login_enabled", "DINGTALK_PASSWORD_LOGIN_ENABLED",
		s.config.DingTalkAuth.PasswordLoginAllowed(),
	)
}

// validateDingTalkEndpoints rejects endpoints that are empty or that the SSRF
// guard refuses to dial. Configuration overrides make these operator-supplied,
// so they get the same treatment as OIDC endpoints.
func validateDingTalkEndpoints(cfg *config.DingTalkAuthConfig) error {
	checks := []struct {
		label    string
		endpoint string
	}{
		{"token", cfg.TokenEndpoint},
		{"userinfo", cfg.UserInfoEndpoint},
	}
	for _, c := range checks {
		endpoint := strings.TrimSpace(c.endpoint)
		if endpoint == "" {
			return fmt.Errorf("DingTalk %s endpoint is required", c.label)
		}
		if err := secutils.ValidateURLForSSRF(endpoint); err != nil {
			return fmt.Errorf("DingTalk %s endpoint failed SSRF validation: %w", c.label, err)
		}
	}
	if err := secutils.ValidateURLForSSRF(strings.TrimSpace(cfg.AuthorizeEndpoint)); err != nil {
		return fmt.Errorf("DingTalk authorize endpoint failed SSRF validation: %w", err)
	}
	return nil
}

// dingTalkProvisioningMode maps the configured string onto the shared
// TenantProvisioningMode used by Register. The "deny" mode has no equivalent
// and is handled by resolveDingTalkUser before provisioning is attempted.
func dingTalkProvisioningMode(cfg *config.DingTalkAuthConfig) types.TenantProvisioningMode {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.ProvisioningMode), config.DingTalkProvisioningTenantless) {
		return types.TenantProvisioningTenantless
	}
	return types.TenantProvisioningCreatePersonal
}

// GetDingTalkAuthorizationURL builds the DingTalk authorization URL.
//
// The nonce is signed into `state` (HMAC, same mechanism as OIDC) so the
// callback can prove the round trip belongs to this browser; the nonce is
// additionally bound to an HttpOnly cookie by the handler. DingTalk echoes
// `state` back on the callback, so the signed payload also carries the
// redirect_uri, preventing a forged callback from redirecting elsewhere.
func (s *userService) GetDingTalkAuthorizationURL(
	ctx context.Context, redirectURI string,
) (*types.OIDCAuthURLResponse, error) {
	cfg, err := s.dingTalkConfig(ctx)
	if err != nil {
		return nil, err
	}
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return nil, errors.New("redirect_uri is required")
	}

	nonce, err := generateRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DingTalk state: %w", err)
	}
	state, err := secutils.SignOIDCState(&secutils.OIDCStatePayload{
		Nonce:       nonce,
		RedirectURI: redirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode DingTalk state: %w", err)
	}

	query := url.Values{}
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("client_id", cfg.AppKey)
	query.Set("scope", "openid")
	query.Set("state", state)
	prompt := "consent"
	query.Set("prompt", prompt)

	authURL := strings.TrimSpace(cfg.AuthorizeEndpoint)
	if strings.Contains(authURL, "?") {
		authURL += "&" + query.Encode()
	} else {
		authURL += "?" + query.Encode()
	}

	return &types.OIDCAuthURLResponse{
		Success:             true,
		ProviderDisplayName: cfg.ProviderDisplayName,
		AuthorizationURL:    authURL,
		State:               state,
		Nonce:               nonce,
	}, nil
}

// LoginWithDingTalk completes a DingTalk login: exchange the authorization
// code for a user access token, read the contact profile, resolve it to a local
// user (binding or provisioning as configured), then issue the same local JWT
// pair the password and OIDC flows issue.
func (s *userService) LoginWithDingTalk(
	ctx context.Context, code, redirectURI string,
) (*types.OIDCCallbackResponse, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, errors.New("code is required")
	}
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return nil, errors.New("redirect_uri is required")
	}

	cfg, err := s.dingTalkConfig(ctx)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.exchangeDingTalkCode(ctx, cfg, code)
	if err != nil {
		return nil, err
	}

	info, err := s.fetchDingTalkUserInfo(ctx, cfg, accessToken)
	if err != nil {
		return nil, err
	}

	user, identity, isNewUser, err := s.resolveDingTalkUser(ctx, cfg, info)
	if err != nil {
		return nil, err
	}
	if !user.IsActive {
		return &types.OIDCCallbackResponse{Success: false, Message: ErrDingTalkUserInactive.Error()}, nil
	}

	// Resolve the target tenant once so the JWT claim and the tenant we return
	// stay in sync (same rationale as Login / LoginWithOIDC).
	resolvedTenantID := s.resolveLoginTenantID(ctx, user)
	accessJWT, refreshJWT, err := s.generateTokensForTenant(ctx, user, resolvedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate local tokens: %w", err)
	}

	// Record the successful login on the binding. Best effort: a bookkeeping
	// failure must not deny an otherwise valid login.
	now := time.Now()
	identity.LastLoginAt = &now
	identity.UpdatedAt = now
	if err := s.identityRepo.Update(ctx, identity); err != nil {
		logger.Warnf(ctx, "DingTalk login: failed to update identity %s: %v", identity.ID, err)
	}

	var tenant *types.Tenant
	if resolvedTenantID > 0 {
		if t, terr := s.tenantService.GetTenantByID(ctx, resolvedTenantID); terr == nil {
			tenant = t
		} else {
			logger.Warnf(ctx, "DingTalk login: failed to load tenant %d for user %s: %v",
				resolvedTenantID, user.ID, terr)
		}
	}
	memberships := s.buildMembershipsForUser(ctx, user, tenant)

	logger.Infof(ctx, "DingTalk login succeeded for user %s (new=%v)", user.ID, isNewUser)
	return &types.OIDCCallbackResponse{
		Success:      true,
		Message:      "登录成功",
		User:         user,
		Tenant:       tenant,
		Memberships:  memberships,
		Token:        accessJWT,
		RefreshToken: refreshJWT,
		IsNewUser:    isNewUser,
	}, nil
}

// exchangeDingTalkCode trades the authorization code for a user access token.
// DingTalk expects a JSON body (not a form) and returns accessToken on 2xx.
func (s *userService) exchangeDingTalkCode(
	ctx context.Context, cfg *config.DingTalkAuthConfig, code string,
) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"clientId":     cfg.AppKey,
		"clientSecret": cfg.AppSecret,
		"code":         code,
		"grantType":    "authorization_code",
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode DingTalk token request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, strings.TrimSpace(cfg.TokenEndpoint), bytes.NewReader(payload),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create DingTalk token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := newDingTalkHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to exchange DingTalk code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read DingTalk token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warnf(ctx, "DingTalk token exchange failed: status=%d code=%s",
			resp.StatusCode, dingTalkErrorCode(body))
		return "", fmt.Errorf("DingTalk token exchange failed: status=%d", resp.StatusCode)
	}

	var tokenResp dingTalkTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode DingTalk token response: %w", err)
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", errors.New("DingTalk token response missing accessToken")
	}
	return tokenResp.AccessToken, nil
}

// fetchDingTalkUserInfo reads the contact profile for the freshly issued token.
func (s *userService) fetchDingTalkUserInfo(
	ctx context.Context, cfg *config.DingTalkAuthConfig, accessToken string,
) (*dingTalkUserInfo, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, strings.TrimSpace(cfg.UserInfoEndpoint), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DingTalk userinfo request: %w", err)
	}
	req.Header.Set("x-acs-dingtalk-access-token", accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := newDingTalkHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DingTalk userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read DingTalk userinfo response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warnf(ctx, "DingTalk userinfo failed: status=%d code=%s",
			resp.StatusCode, dingTalkErrorCode(body))
		return nil, fmt.Errorf("DingTalk userinfo failed: status=%d", resp.StatusCode)
	}

	var info dingTalkUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to decode DingTalk userinfo: %w", err)
	}
	if strings.TrimSpace(info.UnionID) == "" {
		return nil, errors.New("DingTalk userinfo did not return unionId")
	}
	if cfg.CorpID != "" && info.StateCode != "" && !strings.EqualFold(info.StateCode, cfg.CorpID) {
		// StateCode is not corpId in every region, so only reject when the
		// field is present and clearly different: an unconditional check
		// would break deployments that never populate it.
		logger.Warnf(ctx, "DingTalk login: stateCode %q differs from configured corp_id; allowing login",
			secutils.SanitizeForLog(info.StateCode))
	}
	return &info, nil
}

// resolveDingTalkUser maps a DingTalk profile onto a local user, creating the
// binding (and, per policy, the account) on first login.
//
// Order matters:
//  1. An existing binding wins — this is the normal path for every login
//     after the first, and must never be bypassed by email matching.
//  2. bind_by_email lets an unbound unionId adopt a pre-existing local
//     account with the same email, for deployments that already have users.
//  3. Otherwise the provisioning policy decides: create, stay tenantless
//     (still created, but without a workspace), or deny.
func (s *userService) resolveDingTalkUser(
	ctx context.Context, cfg *config.DingTalkAuthConfig, info *dingTalkUserInfo,
) (*types.User, *types.UserIdentity, bool, error) {
	if s.identityRepo == nil {
		return nil, nil, false, errors.New("DingTalk login is not wired to an identity repository")
	}

	unionID := strings.TrimSpace(info.UnionID)
	identity, err := s.identityRepo.FindByProviderSubject(ctx, types.IdentityProviderDingTalk, unionID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to look up DingTalk identity: %w", err)
	}
	if identity != nil {
		user, err := s.userRepo.GetUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to load user for DingTalk identity: %w", err)
		}
		if user == nil {
			return nil, nil, false, errors.New("DingTalk identity points at a missing user")
		}
		s.refreshDingTalkProfile(ctx, identity, info)
		return user, identity, false, nil
	}

	email := strings.TrimSpace(strings.ToLower(info.Email))

	// Allow-list claiming, by the full address the provider returns.
	//
	// Mapping: users.email is the claim key, users.username is whatever the
	// administrator typed (normally the DingTalk nickname). The two are
	// independent — the address decides who may log in, the username decides
	// what the UI shows.
	//
	// First login only: bindDingTalkIdentity records the immutable unionId, and
	// every later login resolves through it above. That binding is what stops a
	// recycled corporate address (same mailbox, different employee) from
	// inheriting the previous holder's account.
	if cfg.BindByEmail && email != "" {
		claimed, claimErr := s.claimDingTalkAccountByEmail(ctx, info, email)
		if claimErr != nil {
			return nil, nil, false, claimErr
		}
		if claimed != nil {
			bound, bindErr := s.bindDingTalkIdentity(ctx, claimed, info)
			if bindErr != nil {
				return nil, nil, false, bindErr
			}
			return claimed, bound, false, nil
		}
	}

	// Fresh-install escape hatch: with an empty users table, deny mode would
	// otherwise deadlock — it refuses to create accounts, and the administrator
	// who would pre-create them cannot log in without one. The check is made on
	// every login against the live table, so no restart is needed to close it:
	// the moment the first account exists, this branch stops matching.
	if cfg.BootstrapFirstUser {
		bootstrapped, isBootstrap, bootErr := s.bootstrapFirstDingTalkUser(ctx, info)
		if bootErr != nil {
			return nil, nil, false, bootErr
		}
		if isBootstrap {
			bound, bindErr := s.bindDingTalkIdentity(ctx, bootstrapped, info)
			if bindErr != nil {
				return nil, nil, false, bindErr
			}
			return bootstrapped, bound, true, nil
		}
	}

	if strings.EqualFold(strings.TrimSpace(cfg.ProvisioningMode), config.DingTalkProvisioningDeny) {
		logger.Warnf(ctx, "DingTalk login rejected: unionId not bound and provisioning_mode=deny")
		return nil, nil, false, ErrDingTalkUnknownIdentity
	}

	user, err := s.provisionDingTalkUser(ctx, cfg, info)
	if err != nil {
		return nil, nil, false, err
	}
	bound, err := s.bindDingTalkIdentity(ctx, user, info)
	if err != nil {
		return nil, nil, false, err
	}
	return user, bound, true, nil
}

// claimDingTalkAccountByEmail resolves an unbound DingTalk login to a
// pre-created local account by the full address DingTalk returns.
//
// Account layout this expects:
//
//	users.username = the administrator's chosen display name (usually the
//	                 DingTalk nickname, e.g. "林成")
//	users.email    = the same address DingTalk reports (e.g. "lin@corp.com")
//
// The address is the claim key, not the username: addresses are unique inside
// an organization and survive display-name edits, while nicknames repeat.
//
// Matching is an exact, case-insensitive comparison of the whole address. A
// partial or fuzzy match would let one employee claim another's account.
//
// Returns (nil, nil) when the profile carries no email or nothing matches, in
// which case the caller falls through to the provisioning policy.
func (s *userService) claimDingTalkAccountByEmail(
	ctx context.Context, info *dingTalkUserInfo, email string,
) (*types.User, error) {
	if email == "" {
		return nil, nil
	}
	candidate, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		if isUserLookupNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to look up account for %q: %w",
			secutils.SanitizeForLog(email), err)
	}
	return s.acceptClaimCandidate(ctx, candidate, info, email, "email")
}

// acceptClaimCandidate is the guard for allow-list claiming: it refuses when
// the account is already bound to a different DingTalk unionId, so two people
// can never end up sharing (or hijacking) one account — including the case
// where a corporate address is recycled to a new employee.
func (s *userService) acceptClaimCandidate(
	ctx context.Context, candidate *types.User, info *dingTalkUserInfo,
	identifier, source string,
) (*types.User, error) {
	if candidate == nil {
		return nil, nil
	}
	existing, err := s.identityRepo.FindByUserAndProvider(
		ctx, candidate.ID, types.IdentityProviderDingTalk,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing DingTalk binding: %w", err)
	}
	if existing != nil && existing.ProviderSubject != strings.TrimSpace(info.UnionID) {
		logger.Warnf(ctx,
			"DingTalk login: %s %q belongs to an account already claimed by another "+
				"DingTalk user; refusing to reassign",
			source, secutils.SanitizeForLog(identifier))
		return nil, ErrDingTalkAccountAlreadyClaimed
	}
	logger.Infof(ctx, "DingTalk login: first-time claim of account %s by %s %q",
		candidate.ID, source, secutils.SanitizeForLog(identifier))
	return candidate, nil
}

// bootstrapFirstDingTalkUser creates and promotes the first account on a
// completely empty deployment.
//
// Preconditions, all checked against live data on every call:
//   - the users table has zero rows
//
// When they hold, the DingTalk user is registered with a personal workspace
// (so there is somewhere to administer from) and marked as system
// administrator. Returns isBootstrap=false when the conditions do not hold, in
// which case the caller falls through to the normal allow-list decision.
//
// The account is NOT bound here; the caller binds it through the usual path so
// a concurrent second login still goes through the unique-index conflict
// resolution.
func (s *userService) bootstrapFirstDingTalkUser(
	ctx context.Context, info *dingTalkUserInfo,
) (*types.User, bool, error) {
	// Cheap emptiness probe: one row is enough to prove the deployment is not
	// fresh. Done first so a populated install pays almost nothing.
	existing, err := s.userRepo.ListUsers(ctx, "", 0, 1)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check for existing users: %w", err)
	}
	if len(existing) > 0 {
		return nil, false, nil
	}

	// Two simultaneous first scans can both pass the probe above. The unique
	// index on users.email/username is the real arbiter: the loser of that race
	// sees ErrUserEmailExists / ErrUserUsernameExists and must NOT be promoted,
	// because the winner already owns the deployment.
	user, err := s.provisionDingTalkUser(ctx, &config.DingTalkAuthConfig{
		ProvisioningMode: config.DingTalkProvisioningCreatePersonal,
	}, info)
	if err != nil {
		if errors.Is(err, ErrUserEmailExists) || errors.Is(err, ErrUserUsernameExists) {
			logger.Warnf(ctx,
				"DingTalk bootstrap: another user was created concurrently; "+
					"falling back to the normal allow-list decision")
			return nil, false, nil
		}
		return nil, false, err
	}

	user.IsSystemAdmin = true
	user.UpdatedAt = time.Now()
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, false, fmt.Errorf("failed to promote bootstrap user %s: %w", user.ID, err)
	}

	logger.Infof(ctx,
		"[bootstrap] promoted first DingTalk user %s (%s) to system administrator "+
			"on an empty deployment", user.ID, secutils.SanitizeForLog(user.Username))
	return user, true, nil
}

// bindDingTalkIdentity stores the binding, tolerating a concurrent winner:
// when two first-time logins race, the unique index rejects the loser, which
// then adopts the winner's existing binding instead of creating a second
// account.
func (s *userService) bindDingTalkIdentity(
	ctx context.Context, user *types.User, info *dingTalkUserInfo,
) (*types.UserIdentity, error) {
	now := time.Now()
	identity := &types.UserIdentity{
		ID:              uuid.New().String(),
		UserID:          user.ID,
		Provider:        types.IdentityProviderDingTalk,
		ProviderSubject: strings.TrimSpace(info.UnionID),
		DisplayName:     sanitizeIdentityDisplayName(info.Nick),
		AvatarURL:       strings.TrimSpace(info.AvatarURL),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.identityRepo.Create(ctx, identity); err != nil {
		if errors.Is(err, apprepo.ErrUserIdentityExists) {
			existing, findErr := s.identityRepo.FindByProviderSubject(
				ctx, types.IdentityProviderDingTalk, identity.ProviderSubject,
			)
			if findErr != nil {
				return nil, fmt.Errorf("failed to re-read DingTalk identity: %w", findErr)
			}
			if existing == nil {
				return nil, errors.New("DingTalk identity conflicted but could not be read back")
			}
			if existing.UserID != user.ID {
				// Someone else already owns this unionId. Bindings are unique
				// per provider+subject, so the caller keeps the existing owner
				// rather than this user.
				logger.Warnf(ctx,
					"DingTalk login: unionId already bound to a different user; refusing to rebind")
				return nil, ErrDingTalkUnknownIdentity
			}
			return existing, nil
		}
		return nil, fmt.Errorf("failed to bind DingTalk identity: %w", err)
	}
	return identity, nil
}

// provisionDingTalkUser creates the local account for a first DingTalk login.
//
// DingTalk only returns an email when the user has one and the application may
// read it, so a deterministic placeholder is synthesised from the unionId
// otherwise. users.email is NOT NULL + UNIQUE, and the placeholder keeps both
// properties without colliding with real addresses.
func (s *userService) provisionDingTalkUser(
	ctx context.Context, cfg *config.DingTalkAuthConfig, info *dingTalkUserInfo,
) (*types.User, error) {
	username := s.generateOIDCUsername(ctx, &types.OIDCUserInfo{
		Username: info.Nick,
		Email:    strings.TrimSpace(info.Email),
	})
	randomPassword, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password for DingTalk user: %w", err)
	}

	email := strings.TrimSpace(info.Email)
	placeholder := dingTalkPlaceholderEmail(info.UnionID)
	if email == "" {
		email = placeholder
	}

	user, err := s.Register(ctx, &types.RegisterRequest{
		Username:           username,
		Email:              email,
		Password:           randomPassword,
		TenantProvisioning: dingTalkProvisioningMode(cfg),
	})
	if err != nil && errors.Is(err, ErrUserEmailExists) && email != placeholder {
		// Another local account already owns this address. Creating under the
		// same address would collide on the users.email unique index, so fall
		// back to the deterministic placeholder instead of failing the login.
		logger.Warnf(ctx,
			"DingTalk login: address already used by another account; "+
				"provisioning with a placeholder address instead")
		user, err = s.Register(ctx, &types.RegisterRequest{
			Username:           username,
			Email:              placeholder,
			Password:           randomPassword,
			TenantProvisioning: dingTalkProvisioningMode(cfg),
		})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to auto-provision DingTalk user: %w", err)
	}

	// The generated password is unknown to the user, so hide self-service
	// password rotation exactly as the OIDC provisioning path does.
	ssoOnly := true
	user.Preferences.SsoOnlyLogin = &ssoOnly
	user.UpdatedAt = time.Now()
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to mark DingTalk-only login preference: %w", err)
	}
	return user, nil
}

// refreshDingTalkProfile updates the cached display fields when the provider
// reports new values. Failures are logged only: a stale nickname must not
// block a login.
func (s *userService) refreshDingTalkProfile(
	ctx context.Context, identity *types.UserIdentity, info *dingTalkUserInfo,
) {
	displayName := sanitizeIdentityDisplayName(info.Nick)
	avatar := strings.TrimSpace(info.AvatarURL)
	changed := false
	if displayName != "" && displayName != identity.DisplayName {
		identity.DisplayName = displayName
		changed = true
	}
	if avatar != "" && avatar != identity.AvatarURL {
		identity.AvatarURL = avatar
		changed = true
	}
	if !changed {
		return
	}
	identity.UpdatedAt = time.Now()
	if err := s.identityRepo.Update(ctx, identity); err != nil {
		logger.Warnf(ctx, "DingTalk login: failed to refresh profile for identity %s: %v",
			identity.ID, err)
	}
}

// dingTalkPlaceholderEmail builds a unique, obviously-synthetic address for
// users whose DingTalk profile carries no email. The domain is reserved by
// convention for non-routable placeholders.
func dingTalkPlaceholderEmail(unionID string) string {
	local := sanitizeUsernameCandidate(unionID)
	if local == "" {
		local = "user"
	}
	return local + "@dingtalk.local"
}

// sanitizeIdentityDisplayName keeps the provider nickname but strips control
// characters so it is safe to log and store.
func sanitizeIdentityDisplayName(nick string) string {
	return strings.TrimSpace(secutils.SanitizeForLog(strings.TrimSpace(nick)))
}

// dingTalkErrorCode extracts DingTalk's error code from an error body without
// letting a malformed body break the surrounding error path.
func dingTalkErrorCode(body []byte) string {
	var errBody dingTalkErrorBody
	if err := json.Unmarshal(body, &errBody); err != nil {
		return "unknown"
	}
	if errBody.Code == "" {
		return "unknown"
	}
	return secutils.SanitizeForLog(errBody.Code)
}
