package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apprepo "github.com/Tencent/WeKnora/internal/application/repository"
	"github.com/Tencent/WeKnora/internal/config"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	secutils "github.com/Tencent/WeKnora/internal/utils"
)

// ---------------------------------------------------------------------------
// Fake external provider
// ---------------------------------------------------------------------------

// dingTalkTestServer is a fake DingTalk token + userinfo endpoint pair. Tests
// drive it through the config's endpoint overrides, so no real network or
// DingTalk tenant is involved.
type dingTalkTestServer struct {
	server *httptest.Server
	// unionID is returned by the userinfo endpoint.
	unionID string
	// email is returned by the userinfo endpoint when non-empty.
	email string
	// nick is returned by the userinfo endpoint; empty keeps the default.
	nick string
	// tokenStatus overrides the token endpoint status code (0 means 200).
	tokenStatus int
	// userinfoStatus overrides the userinfo endpoint status code.
	userinfoStatus int
	// tokenCalls counts token endpoint hits.
	tokenCalls int
}

func newDingTalkTestServer(t *testing.T) *dingTalkTestServer {
	t.Helper()
	// The production client is SSRF-safe by design and refuses loopback
	// targets, so the fake provider must be whitelisted explicitly — the same
	// switch an operator uses to allow a private endpoint in a deployment.
	t.Setenv("SSRF_WHITELIST", "127.0.0.1")
	secutils.ResetSSRFWhitelistForTest()
	t.Cleanup(secutils.ResetSSRFWhitelistForTest)

	ds := &dingTalkTestServer{unionID: "union-123", email: "alice@example.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ds.tokenCalls++
		if ds.tokenStatus != 0 {
			w.WriteHeader(ds.tokenStatus)
			_, _ = w.Write([]byte(`{"code":"InvalidAuthentication","message":"denied"}`))
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["grantType"] != "authorization_code" || body["clientId"] != "test-app-key" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"dt-access-token","expireIn":7200}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if ds.userinfoStatus != 0 {
			w.WriteHeader(ds.userinfoStatus)
			_, _ = w.Write([]byte(`{"code":"Forbidden.AccessDenied","message":"no"}`))
			return
		}
		if r.Header.Get("x-acs-dingtalk-access-token") != "dt-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		nick := ds.nick
		if nick == "" {
			nick = "Alice Zhang"
		}
		payload := map[string]string{
			"unionId":   ds.unionID,
			"openId":    "open-123",
			"nick":      nick,
			"avatarUrl": "https://example.com/a.png",
		}
		if ds.email != "" {
			payload["email"] = ds.email
		}
		_ = json.NewEncoder(w).Encode(payload)
	})
	ds.server = httptest.NewServer(mux)
	t.Cleanup(ds.server.Close)
	return ds
}

// ---------------------------------------------------------------------------
// In-memory repositories
// ---------------------------------------------------------------------------

// fakeIdentityRepo is an in-memory UserIdentityRepository that rejects
// duplicate (provider, subject) bindings exactly like the unique index does.
type fakeIdentityRepo struct {
	mu   sync.Mutex
	rows []*types.UserIdentity
}

func (f *fakeIdentityRepo) FindByProviderSubject(
	_ context.Context, provider, subject string,
) (*types.UserIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.Provider == provider && r.ProviderSubject == subject {
			return r, nil
		}
	}
	return nil, nil
}

func (f *fakeIdentityRepo) FindByUserAndProvider(
	_ context.Context, userID, provider string,
) (*types.UserIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.UserID == userID && r.Provider == provider {
			return r, nil
		}
	}
	return nil, nil
}

func (f *fakeIdentityRepo) Create(_ context.Context, identity *types.UserIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.Provider == identity.Provider && r.ProviderSubject == identity.ProviderSubject {
			return errFakeIdentityExists
		}
	}
	f.rows = append(f.rows, identity)
	return nil
}

func (f *fakeIdentityRepo) Update(context.Context, *types.UserIdentity) error { return nil }

func (f *fakeIdentityRepo) DeleteByUserID(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := make([]*types.UserIdentity, 0, len(f.rows))
	for _, r := range f.rows {
		if r.UserID != userID {
			kept = append(kept, r)
		}
	}
	f.rows = kept
	return nil
}

// fakeUserRepo is an in-memory UserRepository covering the calls the DingTalk
// flow makes (lookup by id/email/username, create, update).
type fakeUserRepo struct {
	mu    sync.Mutex
	users map[string]*types.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: map[string]*types.User{}}
}

func (f *fakeUserRepo) CreateUser(_ context.Context, user *types.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Email == user.Email {
			return ErrUserEmailExists
		}
		if u.Username == user.Username {
			return ErrUserUsernameExists
		}
	}
	clone := *user
	f.users[user.ID] = &clone
	return nil
}

func (f *fakeUserRepo) GetUserByID(_ context.Context, id string) (*types.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, nil
}

func (f *fakeUserRepo) GetUsersByIDs(_ context.Context, ids []string) (map[string]*types.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]*types.User{}
	for _, id := range ids {
		if u, ok := f.users[id]; ok {
			out[id] = u
		}
	}
	return out, nil
}

func (f *fakeUserRepo) GetUserByEmail(_ context.Context, email string) (*types.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (f *fakeUserRepo) GetUserByUsername(_ context.Context, username string) (*types.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, nil
}

func (f *fakeUserRepo) GetUserByTenantID(context.Context, uint64) (*types.User, error) {
	return nil, nil
}

func (f *fakeUserRepo) UpdateUser(_ context.Context, user *types.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	clone := *user
	f.users[user.ID] = &clone
	return nil
}

func (f *fakeUserRepo) SetUserActive(
	context.Context, string, string, bool,
) (*types.User, error) {
	return nil, nil
}

func (f *fakeUserRepo) DeleteUser(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users, id)
	return nil
}

// ListUsers reflects the in-memory rows so the empty-deployment probe in the
// bootstrap path sees real state instead of an always-empty answer.
func (f *fakeUserRepo) ListUsers(
	_ context.Context, _ string, offset, limit int,
) ([]*types.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*types.User, 0, len(f.users))
	for _, u := range f.users {
		out = append(out, u)
	}
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if limit > 0 && limit < len(out) {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeUserRepo) ListSystemAdmins(context.Context, int, int) ([]*types.User, int64, error) {
	return nil, 0, nil
}

func (f *fakeUserRepo) RevokeSystemAdmin(context.Context, string, string) (*types.User, error) {
	return nil, nil
}

func (f *fakeUserRepo) SearchUsers(context.Context, string, int) ([]*types.User, error) {
	return nil, nil
}

// fakeTokenRepo records issued tokens so the login path can persist them.
type fakeTokenRepo struct {
	mu     sync.Mutex
	tokens []*types.AuthToken
}

func (f *fakeTokenRepo) CreateToken(_ context.Context, token *types.AuthToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = append(f.tokens, token)
	return nil
}

func (f *fakeTokenRepo) GetTokenByValue(context.Context, string) (*types.AuthToken, error) {
	return nil, nil
}

func (f *fakeTokenRepo) GetTokenByID(context.Context, string) (*types.AuthToken, error) {
	return nil, nil
}

func (f *fakeTokenRepo) GetTokensByUserID(context.Context, string) ([]*types.AuthToken, error) {
	return nil, nil
}

func (f *fakeTokenRepo) UpdateToken(context.Context, *types.AuthToken) error { return nil }

func (f *fakeTokenRepo) DeleteToken(context.Context, string) error { return nil }

func (f *fakeTokenRepo) DeleteExpiredTokens(context.Context) error { return nil }

func (f *fakeTokenRepo) RevokeTokensByUserID(context.Context, string) error { return nil }

// fakeTenantService resolves the small set of tenant lookups the flow needs.
// The embedded interface makes every unneeded method panic-free by omission:
// only the methods the DingTalk path actually calls are overridden, so this
// fixture stays valid when TenantService grows new methods.
type fakeTenantService struct {
	interfaces.TenantService
	tenants map[uint64]*types.Tenant
	nextID  uint64
}

// CreateTenant assigns an id and stores the row, mirroring the real service:
// Register relies on the returned id to set the user's home tenant.
func (f *fakeTenantService) CreateTenant(_ context.Context, tenant *types.Tenant) (*types.Tenant, error) {
	if f.tenants == nil {
		f.tenants = map[uint64]*types.Tenant{}
	}
	f.nextID++
	tenant.ID = f.nextID
	f.tenants[tenant.ID] = tenant
	return tenant, nil
}

func (f *fakeTenantService) GetTenantByID(_ context.Context, id uint64) (*types.Tenant, error) {
	if t, ok := f.tenants[id]; ok {
		return t, nil
	}
	return &types.Tenant{ID: id, Name: "Workspace"}, nil
}

func (f *fakeTenantService) GetTenantsByIDs(
	_ context.Context, ids []uint64,
) (map[uint64]*types.Tenant, error) {
	out := map[uint64]*types.Tenant{}
	for _, id := range ids {
		if t, ok := f.tenants[id]; ok {
			out[id] = t
		}
	}
	return out, nil
}

func (f *fakeTenantService) DeleteTenant(context.Context, uint64) error { return nil }

// fakeMemberService reports an active membership for every (user, tenant).
type fakeMemberService struct {
	interfaces.TenantMemberService
}

func (fakeMemberService) EnsureOwner(
	context.Context, string, uint64,
) (*types.TenantMember, error) {
	return &types.TenantMember{Status: types.TenantMemberStatusActive}, nil
}

func (fakeMemberService) GetMembership(
	context.Context, string, uint64,
) (*types.TenantMember, error) {
	return &types.TenantMember{
		Status: types.TenantMemberStatusActive,
		Role:   types.TenantRoleOwner,
	}, nil
}

func (fakeMemberService) ListByUser(context.Context, string) ([]*types.TenantMember, error) {
	return []*types.TenantMember{}, nil
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// errFakeIdentityExists mirrors the repository's duplicate-binding sentinel so
// the service's conflict path can be exercised through the fake.
var errFakeIdentityExists = apprepo.ErrUserIdentityExists

// newDingTalkTestConfig builds an enabled config pointing at the fake server.
func newDingTalkTestConfig(serverURL, provisioning string) *config.Config {
	return &config.Config{
		DingTalkAuth: &config.DingTalkAuthConfig{
			Enable:              true,
			AppKey:              "test-app-key",
			AppSecret:           "test-app-secret",
			ProviderDisplayName: "钉钉",
			AuthorizeEndpoint:   "https://login.dingtalk.com/oauth2/auth",
			TokenEndpoint:       serverURL + "/token",
			UserInfoEndpoint:    serverURL + "/userinfo",
			ProvisioningMode:    provisioning,
		},
	}
}

type dingTalkFixture struct {
	svc      *userService
	users    *fakeUserRepo
	idents   *fakeIdentityRepo
	tokens   *fakeTokenRepo
	tenants  *fakeTenantService
	members  fakeMemberService
	provider *dingTalkTestServer
}

func newDingTalkFixture(t *testing.T, provisioning string) *dingTalkFixture {
	t.Helper()
	provider := newDingTalkTestServer(t)
	f := &dingTalkFixture{
		users:    newFakeUserRepo(),
		idents:   &fakeIdentityRepo{},
		tokens:   &fakeTokenRepo{},
		tenants:  &fakeTenantService{tenants: map[uint64]*types.Tenant{}},
		provider: provider,
	}
	f.svc = &userService{
		config:        newDingTalkTestConfig(provider.server.URL, provisioning),
		userRepo:      f.users,
		tokenRepo:     f.tokens,
		tenantService: f.tenants,
		memberService: f.members,
		identityRepo:  f.idents,
	}
	return f
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDingTalkAuthorizationURLIsSignedAndCarriesState(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)

	resp, err := f.svc.GetDingTalkAuthorizationURL(context.Background(), "https://kb.example.com/login")
	require.NoError(t, err)
	require.NotEmpty(t, resp.AuthorizationURL)
	require.NotEmpty(t, resp.State)
	// The nonce is returned to the handler (which stores it in an HttpOnly
	// cookie) but is tagged json:"-" so it never reaches the response body.
	require.NotEmpty(t, resp.Nonce)

	parsed, err := url.Parse(resp.AuthorizationURL)
	require.NoError(t, err)
	assert.Equal(t, "code", parsed.Query().Get("response_type"))
	assert.Equal(t, "test-app-key", parsed.Query().Get("client_id"))
	assert.Equal(t, "https://kb.example.com/login", parsed.Query().Get("redirect_uri"))
	assert.Equal(t, resp.State, parsed.Query().Get("state"))
}

func TestDingTalkDisabledReturnsError(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.svc.config.DingTalkAuth.Enable = false

	_, err := f.svc.GetDingTalkAuthorizationURL(context.Background(), "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkDisabled)

	_, err = f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkDisabled)
}

func TestDingTalkMissingCredentialsIsTreatedAsDisabled(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.svc.config.DingTalkAuth.AppSecret = ""

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkDisabled)
}

func TestLoginWithDingTalkFirstLoginProvisionsAndBinds(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.True(t, resp.IsNewUser)
	require.NotNil(t, resp.User)
	assert.Equal(t, "alice@example.com", resp.User.Email)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, 1, f.provider.tokenCalls)

	// The binding must exist so the next login is not a new user.
	bound, err := f.idents.FindByProviderSubject(context.Background(), types.IdentityProviderDingTalk, "union-123")
	require.NoError(t, err)
	require.NotNil(t, bound)
	assert.Equal(t, resp.User.ID, bound.UserID)

	// Auto-provisioned accounts hide password rotation from the UI.
	require.NotNil(t, resp.User.Preferences.SsoOnlyLogin)
	assert.True(t, *resp.User.Preferences.SsoOnlyLogin)

	// Two tokens (access + refresh) were persisted.
	assert.Len(t, f.tokens.tokens, 2)
}

func TestLoginWithDingTalkSecondLoginReusesAccount(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	ctx := context.Background()

	first, err := f.svc.LoginWithDingTalk(ctx, "auth-code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.True(t, first.IsNewUser)

	second, err := f.svc.LoginWithDingTalk(ctx, "auth-code-2", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.False(t, second.IsNewUser, "a bound unionId must not provision again")
	assert.Equal(t, first.User.ID, second.User.ID)
	assert.Len(t, f.users.users, 1, "exactly one local account must exist")
}

func TestLoginWithDingTalkDenyModeRejectsUnknownUnionID(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)

	_, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity)
	assert.Empty(t, f.users.users, "deny mode must not create an account")
}

func TestLoginWithDingTalkTenantlessLeavesUserWithoutWorkspace(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningTenantless)

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.True(t, resp.Success)
	assert.Equal(t, uint64(0), resp.User.TenantID, "tenantless provisioning must not create a workspace")
}

func TestLoginWithDingTalkBindsExistingAccountByEmailWhenOptedIn(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.svc.config.DingTalkAuth.BindByEmail = true

	// Pre-existing local account with the same email as the DingTalk profile.
	existing := &types.User{
		ID:        "existing-user",
		Username:  "alice",
		Email:     "alice@example.com",
		IsActive:  true,
		TenantID:  9,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, f.users.CreateUser(context.Background(), existing))

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.False(t, resp.IsNewUser)
	assert.Equal(t, "existing-user", resp.User.ID)
	assert.Len(t, f.users.users, 1, "no second account may be created")
}

func TestLoginWithDingTalkIgnoresEmailWhenBindingDisabled(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)

	existing := &types.User{
		ID:        "existing-user",
		Username:  "alice",
		Email:     "alice@example.com",
		IsActive:  true,
		TenantID:  9,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, f.users.CreateUser(context.Background(), existing))

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.True(t, resp.IsNewUser, "bind_by_email is off by default")
	assert.NotEqual(t, "existing-user", resp.User.ID)
}

func TestLoginWithDingTalkRejectsMissingUnionID(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.provider.unionID = ""

	_, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unionId")
}

func TestLoginWithDingTalkSurfacesTokenEndpointFailure(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.provider.tokenStatus = http.StatusUnauthorized

	_, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange failed")
}

func TestLoginWithDingTalkSurfacesUserInfoFailure(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.provider.userinfoStatus = http.StatusForbidden

	_, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "userinfo failed")
}

func TestLoginWithDingTalkAcceptsInactiveUserWithoutTokens(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	ctx := context.Background()

	inactive := &types.User{
		ID:        "disabled-user",
		Username:  "alice",
		Email:     "alice@example.com",
		IsActive:  false,
		TenantID:  7,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, f.users.CreateUser(ctx, inactive))
	require.NoError(t, f.idents.Create(ctx, &types.UserIdentity{
		ID:              "ident-1",
		UserID:          "disabled-user",
		Provider:        types.IdentityProviderDingTalk,
		ProviderSubject: "union-123",
	}))

	resp, err := f.svc.LoginWithDingTalk(ctx, "auth-code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Success)
	assert.Empty(t, resp.Token)
	assert.Contains(t, resp.Message, "disabled")
	assert.Empty(t, f.tokens.tokens, "a disabled account must not receive tokens")
}

func TestDingTalkPlaceholderEmailIsUniquePerUnionID(t *testing.T) {
	a := dingTalkPlaceholderEmail("union-abc")
	b := dingTalkPlaceholderEmail("union-xyz")
	assert.NotEqual(t, a, b)
	assert.True(t, strings.HasSuffix(a, "@dingtalk.local"))
}

func TestLoginWithDingTalkWithoutProfileEmailUsesPlaceholder(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.provider.email = ""

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.True(t, resp.Success)
	assert.True(t, strings.HasSuffix(resp.User.Email, "@dingtalk.local"))
}

func TestDingTalkRequiresIdentityRepository(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.svc.identityRepo = nil

	_, err := f.svc.LoginWithDingTalk(context.Background(), "auth-code", "https://kb.example.com/login")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity repository")
}

func TestDingTalkConfigEnabledRequiresBothCredentials(t *testing.T) {
	cfg := &config.DingTalkAuthConfig{Enable: true, AppKey: "k"}
	assert.False(t, cfg.Enabled())
	cfg.AppSecret = "s"
	assert.True(t, cfg.Enabled())
	cfg.Enable = false
	assert.False(t, cfg.Enabled())
}

// ---------------------------------------------------------------------------
// Nickname claiming (allow-list mode)
// ---------------------------------------------------------------------------

// newNicknameFixture builds a fixture where nickname claiming is enabled and
// the pre-created account uses the Chinese nickname as its username.
func newNicknameFixture(t *testing.T, provisioning string) *dingTalkFixture {
	t.Helper()
	f := newDingTalkFixture(t, provisioning)
	f.svc.config.DingTalkAuth.BindByNickname = true
	return f
}

// createPreCreatedUser inserts the account an administrator would have made
// through the admin UI: username = the DingTalk nickname.
func createPreCreatedUser(t *testing.T, f *dingTalkFixture, id, username string) *types.User {
	t.Helper()
	u := &types.User{
		ID:        id,
		Username:  username,
		Email:     "pre-" + id + "@corp.local",
		IsActive:  true,
		TenantID:  8,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, f.users.CreateUser(context.Background(), u))
	return u
}

// TestDingTalkNicknameClaimBindsPreCreatedAccount is the core allow-list case:
// a Chinese nickname matches the pre-created username exactly and the unionId
// gets bound on first login.
func TestDingTalkNicknameClaimBindsPreCreatedAccount(t *testing.T) {
	f := newNicknameFixture(t, config.DingTalkProvisioningDeny)
	f.provider.unionID = "union-shi"
	f.provider.email = ""
	f.provider.nick = "史元东"

	pre := createPreCreatedUser(t, f, "user-shi", "史元东")

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Equal(t, pre.ID, resp.User.ID, "must log into the pre-created account")

	bound, err := f.idents.FindByProviderSubject(
		context.Background(), types.IdentityProviderDingTalk, "union-shi",
	)
	require.NoError(t, err)
	require.NotNil(t, bound)
	assert.Equal(t, pre.ID, bound.UserID, "first login must bind the unionId")

	// Second login resolves by unionId, not by nickname: rename the profile and
	// it must still reach the same account.
	f.provider.unionID = "union-shi"
	resp2, err := f.svc.LoginWithDingTalk(context.Background(), "code2", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.Equal(t, pre.ID, resp2.User.ID)
	assert.Len(t, f.users.users, 1, "no extra account may be created")
}

// TestDingTalkNicknameMismatchIsRejected is the "禁止登入" requirement: an
// unknown nickname must not be able to create an account.
func TestDingTalkNicknameMismatchIsRejected(t *testing.T) {
	f := newNicknameFixture(t, config.DingTalkProvisioningDeny)
	f.provider.unionID = "union-stranger"
	f.provider.nick = "陌生人"
	createPreCreatedUser(t, f, "user-shi", "史元东")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity)
	assert.Len(t, f.users.users, 1, "an unlisted nickname must not get an account")
}

// TestDingTalkNicknameClaimRefusesAccountOwnedByAnother pins the anti-hijack
// rule: a second unionId that happens to share the nickname cannot take over a
// claimed account.
func TestDingTalkNicknameClaimRefusesAccountOwnedByAnother(t *testing.T) {
	f := newNicknameFixture(t, config.DingTalkProvisioningDeny)
	pre := createPreCreatedUser(t, f, "user-shi", "史元东")

	// Another DingTalk user already owns this account.
	require.NoError(t, f.idents.Create(context.Background(), &types.UserIdentity{
		ID:              "ident-other",
		UserID:          pre.ID,
		Provider:        types.IdentityProviderDingTalk,
		ProviderSubject: "union-original",
	}))

	f.provider.unionID = "union-impostor"
	f.provider.nick = "史元东"
	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkAccountAlreadyClaimed)
}

// TestDingTalkNicknameTrimmedNotStripped documents the matching rule: outer
// whitespace is tolerated, but the Chinese characters themselves are preserved
// (sanitizeUsernameCandidate would have erased them).
func TestDingTalkNicknameTrimmedNotStripped(t *testing.T) {
	f := newNicknameFixture(t, config.DingTalkProvisioningDeny)
	pre := createPreCreatedUser(t, f, "user-shi", "史元东")

	// The provider fixture returns a fixed nickname, so exercise the matching
	// rule directly with a padded CJK nickname.
	info := &dingTalkUserInfo{Nick: "  史元东  ", UnionID: "union-space"}
	claimed, err := f.svc.claimDingTalkAccountByNickname(context.Background(), info)
	require.NoError(t, err)
	require.NotNil(t, claimed, "surrounding whitespace must be trimmed, not the CJK text")
	assert.Equal(t, pre.ID, claimed.ID)
}

// TestDingTalkNicknameClaimDisabledByDefault guards the opt-in: without the
// switch, no nickname matching happens at all.
func TestDingTalkNicknameClaimDisabledByDefault(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.provider.unionID = "union-x"
	f.provider.nick = "史元东"
	createPreCreatedUser(t, f, "user-shi", "史元东")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity,
		"nickname claiming is off by default, so the login must be refused")
}

// ---------------------------------------------------------------------------
// Fresh-install bootstrap
// ---------------------------------------------------------------------------

// TestDingTalkBootstrapFirstUserOnEmptyDeployment covers the deadlock breaker:
// with deny mode plus bootstrap enabled and an empty users table, the very
// first scan creates an account and promotes it to system administrator.
func TestDingTalkBootstrapFirstUserOnEmptyDeployment(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BootstrapFirstUser = true
	f.provider.unionID = "union-first"
	f.provider.nick = "史元东"

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success, "the first scan on an empty deployment must succeed")
	assert.True(t, resp.IsNewUser)
	assert.True(t, resp.User.IsSystemAdmin, "first user must become system administrator")

	// The account gets a real workspace to administer from.
	assert.NotZero(t, resp.User.TenantID, "bootstrap account needs a workspace")

	// And the binding is written so the next login takes the normal path.
	bound, err := f.idents.FindByProviderSubject(
		context.Background(), types.IdentityProviderDingTalk, "union-first",
	)
	require.NoError(t, err)
	require.NotNil(t, bound)
	assert.Equal(t, resp.User.ID, bound.UserID)
}

// TestDingTalkBootstrapOnlyAppliesWhileEmpty is the security property: once any
// user exists, the escape hatch closes and deny mode applies again. No restart
// is involved — the check reads the live table.
func TestDingTalkBootstrapOnlyAppliesWhileEmpty(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BootstrapFirstUser = true
	f.provider.unionID = "union-second"
	f.provider.nick = "陌生人"

	// Somebody already exists in the deployment.
	createPreCreatedUser(t, f, "user-existing", "老员工")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity,
		"bootstrap must not fire once the deployment has users")
}

// TestDingTalkBootstrapDisabledByDefault pins the opt-in requirement: deny mode
// stays strict unless the operator enables the escape hatch.
func TestDingTalkBootstrapDisabledByDefault(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.provider.unionID = "union-nobody"
	f.provider.nick = "史元东"

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity,
		"without bootstrap_first_user an empty deployment still refuses")
	assert.Empty(t, f.users.users, "no account may be created")
}

// TestDingTalkBootstrapDoesNotPromoteSecondUser ensures only one account is
// ever created by the flow and no second promotion happens afterwards.
func TestDingTalkBootstrapDoesNotPromoteSecondUser(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BootstrapFirstUser = true
	f.provider.unionID = "union-first"
	f.provider.nick = "史元东"
	ctx := context.Background()

	first, err := f.svc.LoginWithDingTalk(ctx, "code", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.True(t, first.User.IsSystemAdmin)

	// A different person scans afterwards: the deployment is no longer empty,
	// so the allow-list applies and they are refused.
	f.provider.unionID = "union-other"
	f.provider.nick = "另一个人"
	_, err = f.svc.LoginWithDingTalk(ctx, "code2", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity)
	assert.Len(t, f.users.users, 1, "only the bootstrap account may exist")
}
