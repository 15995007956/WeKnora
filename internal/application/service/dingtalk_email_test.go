package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Tencent/WeKnora/internal/config"
	"github.com/Tencent/WeKnora/internal/types"
)

// ---------------------------------------------------------------------------
// Unicode usernames
// ---------------------------------------------------------------------------

// TestSanitizeUsernamePreservingUnicodeKeepsCJK pins the reason this helper
// exists: the ASCII-only sanitizer turns "林成" into "", which forced every
// Chinese DingTalk user onto an email-derived fallback name.
func TestSanitizeUsernamePreservingUnicodeKeepsCJK(t *testing.T) {
	assert.Equal(t, "林成", sanitizeUsernamePreservingUnicode("林成"))
	assert.Equal(t, "史元东", sanitizeUsernamePreservingUnicode("  史元东  "))
	assert.Equal(t, "honestsky", sanitizeUsernamePreservingUnicode("HonestSky"))
	// The old helper still strips CJK; this documents the difference.
	assert.Equal(t, "", sanitizeUsernameCandidate("林成"))
}

// TestSanitizeUsernamePreservingUnicodeDropsUnsafe covers whitespace, control
// characters and separators that must not reach an identifier.
func TestSanitizeUsernamePreservingUnicodeDropsUnsafe(t *testing.T) {
	assert.Equal(t, "林成", sanitizeUsernamePreservingUnicode("林·成"))
	assert.Equal(t, "张-三", sanitizeUsernamePreservingUnicode("张 三"))
	assert.Equal(t, "lin-cheng", sanitizeUsernamePreservingUnicode("lin cheng"))
	assert.Equal(t, "lin-cheng", sanitizeUsernamePreservingUnicode("lin@cheng"))
	assert.Equal(t, "", sanitizeUsernamePreservingUnicode("   "))
}

// TestSanitizeUsernamePreservingUnicodeCapsRunLength guards varchar(100) /
// 2-50 rune validation: 50 Chinese characters must survive intact.
func TestSanitizeUsernamePreservingUnicodeCapsRunLength(t *testing.T) {
	cjk := ""
	for i := 0; i < 60; i++ {
		cjk += "林"
	}
	got := sanitizeUsernamePreservingUnicode(cjk)
	assert.Equal(t, 50, len([]rune(got)), "must truncate by rune, not by byte")
}

// TestDingTalkProvisioningUsesChineseNickname proves the nickname reaches the
// account name end to end instead of collapsing to the email prefix.
func TestDingTalkProvisioningUsesChineseNickname(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningCreatePersonal)
	f.provider.unionID = "union-lincheng"
	f.provider.nick = "林成"
	f.provider.email = "honestsky@sziton.com"

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.True(t, resp.Success)
	assert.Equal(t, "林成", resp.User.Username, "Chinese nickname must become the username")
	assert.Equal(t, "honestsky@sziton.com", resp.User.Email)
}

// ---------------------------------------------------------------------------
// Email claiming (allow-list)
// ---------------------------------------------------------------------------

// newEmailClaimFixture builds a fixture where claiming is enabled and deny mode
// is active: only accounts an administrator created in advance may log in.
func newEmailClaimFixture(t *testing.T) *dingTalkFixture {
	t.Helper()
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BindByEmail = true
	return f
}

// createAccountWithEmail inserts an administrator-created account whose
// username is a display name and whose email is the claim key.
func createAccountWithEmail(t *testing.T, f *dingTalkFixture, id, username, email string) *types.User {
	t.Helper()
	u := &types.User{
		ID:        id,
		Username:  username,
		Email:     email,
		IsActive:  true,
		TenantID:  7,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, f.users.CreateUser(context.Background(), u))
	return u
}

// TestDingTalkEmailClaimBindsPreCreatedAccount is the core allow-list case:
// the address decides the account, the username stays the human nickname.
func TestDingTalkEmailClaimBindsPreCreatedAccount(t *testing.T) {
	f := newEmailClaimFixture(t)
	f.provider.unionID = "union-lin"
	f.provider.email = "honestsky@sziton.com"
	f.provider.nick = "林成"

	pre := createAccountWithEmail(t, f, "user-lin", "林成", "honestsky@sziton.com")

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.True(t, resp.Success)
	assert.Equal(t, pre.ID, resp.User.ID, "must log into the pre-created account")
	assert.Equal(t, "林成", resp.User.Username, "username is the nickname, not the address")

	bound, err := f.idents.FindByProviderSubject(
		context.Background(), types.IdentityProviderDingTalk, "union-lin",
	)
	require.NoError(t, err)
	require.NotNil(t, bound)
	assert.Equal(t, pre.ID, bound.UserID)

	// Second login resolves by unionId, so a nickname edit changes nothing.
	f.provider.nick = "林成（改名）"
	resp2, err := f.svc.LoginWithDingTalk(context.Background(), "code2", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.Equal(t, pre.ID, resp2.User.ID)
	assert.Len(t, f.users.users, 1, "no extra account may be created")
}

// TestDingTalkEmailClaimIsCaseInsensitive covers directory casing differences.
func TestDingTalkEmailClaimIsCaseInsensitive(t *testing.T) {
	f := newEmailClaimFixture(t)
	f.provider.unionID = "union-case"
	f.provider.email = "HonestSky@SZITON.com"
	f.provider.nick = "林成"

	pre := createAccountWithEmail(t, f, "user-case", "林成", "honestsky@sziton.com")
	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.Equal(t, pre.ID, resp.User.ID)
}

// TestDingTalkEmailClaimRequiresWholeAddress is the anti-hijack property of
// whole-address matching: a different domain must not reach the account, even
// though the local part is identical.
func TestDingTalkEmailClaimRequiresWholeAddress(t *testing.T) {
	f := newEmailClaimFixture(t)
	f.provider.unionID = "union-other-domain"
	f.provider.email = "honestsky@evil.com"
	f.provider.nick = "林成"

	createAccountWithEmail(t, f, "user-lin", "林成", "honestsky@sziton.com")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity,
		"a matching local part on another domain must not claim the account")
}

// TestDingTalkEmailClaimUnknownIsRejected keeps deny mode strict.
func TestDingTalkEmailClaimUnknownIsRejected(t *testing.T) {
	f := newEmailClaimFixture(t)
	f.provider.unionID = "union-none"
	f.provider.email = "stranger@sziton.com"
	f.provider.nick = "陌生人"

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity)
	assert.Empty(t, f.users.users)
}

// TestDingTalkEmailClaimRefusesAccountOwnedByAnother mirrors the recycle risk:
// an address handed to a new employee must not inherit the old holder's account.
func TestDingTalkEmailClaimRefusesAccountOwnedByAnother(t *testing.T) {
	f := newEmailClaimFixture(t)
	f.provider.unionID = "union-new-holder"
	f.provider.email = "shared@sziton.com"
	f.provider.nick = "新人"

	pre := createAccountWithEmail(t, f, "user-old", "旧员工", "shared@sziton.com")
	require.NoError(t, f.idents.Create(context.Background(), &types.UserIdentity{
		ID:              "ident-old",
		UserID:          pre.ID,
		Provider:        types.IdentityProviderDingTalk,
		ProviderSubject: "union-old-holder",
	}))

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkAccountAlreadyClaimed)
}

// TestDingTalkEmailClaimSkipsProfileWithoutEmail covers profiles where the
// application is not allowed to read the address.
func TestDingTalkEmailClaimSkipsProfileWithoutEmail(t *testing.T) {
	f := newEmailClaimFixture(t)
	f.provider.unionID = "union-noemail"
	f.provider.email = ""
	f.provider.nick = "林成"
	createAccountWithEmail(t, f, "user-lin", "林成", "honestsky@sziton.com")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity,
		"without an address there is nothing to match, so deny mode refuses")
}

// TestDingTalkNicknameIsNotAClaimKey pins the removal of nickname claiming: an
// account whose username equals the nickname must not be reachable by name.
func TestDingTalkNicknameIsNotAClaimKey(t *testing.T) {
	f := newEmailClaimFixture(t)
	f.provider.unionID = "union-nick-only"
	f.provider.email = "honestsky@sziton.com"
	f.provider.nick = "林成"

	// Username matches the nickname, but the address does not.
	createAccountWithEmail(t, f, "user-lin", "林成", "someone-else@sziton.com")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity,
		"claiming is by address only; a nickname match must not be enough")
}

// TestDingTalkEmailClaimDisabledByDefault guards the opt-in.
func TestDingTalkEmailClaimDisabledByDefault(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.provider.unionID = "union-off"
	f.provider.email = "honestsky@sziton.com"
	f.provider.nick = "林成"
	createAccountWithEmail(t, f, "user-lin", "林成", "honestsky@sziton.com")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity)
}
