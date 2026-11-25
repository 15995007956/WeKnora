package service

import (
	"context"
	"testing"

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
// Email-prefix claiming
// ---------------------------------------------------------------------------

// TestDingTalkEmailPrefixClaimBindsExistingAccount is the new allow-list path:
// the administrator creates a user named after the email local part, and the
// first DingTalk login claims it.
func TestDingTalkEmailPrefixClaimBindsExistingAccount(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BindByEmailPrefix = true
	f.provider.unionID = "union-honest"
	f.provider.email = "honestsky@sziton.com"
	f.provider.nick = "林成"

	pre := createPreCreatedUser(t, f, "user-honest", "honestsky")

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	require.True(t, resp.Success)
	assert.Equal(t, pre.ID, resp.User.ID, "must log into the pre-created account")

	bound, err := f.idents.FindByProviderSubject(
		context.Background(), types.IdentityProviderDingTalk, "union-honest",
	)
	require.NoError(t, err)
	require.NotNil(t, bound)
	assert.Equal(t, pre.ID, bound.UserID)
}

// TestDingTalkEmailPrefixIsCaseInsensitive covers the corporate-directory case
// where the local part differs only by capitalisation.
func TestDingTalkEmailPrefixIsCaseInsensitive(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BindByEmailPrefix = true
	f.provider.unionID = "union-case"
	f.provider.email = "HonestSky@SZITON.com"

	pre := createPreCreatedUser(t, f, "user-case", "honestsky")
	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.Equal(t, pre.ID, resp.User.ID)
}

// TestDingTalkEmailPrefixUnknownIsRejected keeps deny mode strict.
func TestDingTalkEmailPrefixUnknownIsRejected(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BindByEmailPrefix = true
	f.provider.unionID = "union-none"
	f.provider.email = "stranger@sziton.com"

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity)
	assert.Empty(t, f.users.users)
}

// TestDingTalkEmailPrefixPrefersEmailOverNickname documents the ordering: when
// both switches are on, the stable email local part wins over a nickname that
// happens to match a different account.
func TestDingTalkEmailPrefixPrefersEmailOverNickname(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BindByEmailPrefix = true
	f.svc.config.DingTalkAuth.BindByNickname = true
	f.provider.unionID = "union-order"
	f.provider.email = "honestsky@sziton.com"
	f.provider.nick = "林成"

	byEmail := createPreCreatedUser(t, f, "user-by-email", "honestsky")
	createPreCreatedUser(t, f, "user-by-nick", "林成")

	resp, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.NoError(t, err)
	assert.Equal(t, byEmail.ID, resp.User.ID, "email prefix must be tried first")
}

// TestDingTalkEmailPrefixRefusesAccountOwnedByAnother mirrors the nickname
// guard: a claimed account is never reassigned.
func TestDingTalkEmailPrefixRefusesAccountOwnedByAnother(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BindByEmailPrefix = true
	f.provider.unionID = "union-new"
	f.provider.email = "honestsky@sziton.com"

	pre := createPreCreatedUser(t, f, "user-owned", "honestsky")
	require.NoError(t, f.idents.Create(context.Background(), &types.UserIdentity{
		ID:              "ident-owner",
		UserID:          pre.ID,
		Provider:        types.IdentityProviderDingTalk,
		ProviderSubject: "union-original",
	}))

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkAccountAlreadyClaimed)
}

// TestDingTalkEmailPrefixWithoutEmailIsSkipped covers profiles with no address.
func TestDingTalkEmailPrefixWithoutEmailIsSkipped(t *testing.T) {
	f := newDingTalkFixture(t, config.DingTalkProvisioningDeny)
	f.svc.config.DingTalkAuth.BindByEmailPrefix = true
	f.provider.unionID = "union-noemail"
	f.provider.email = ""
	createPreCreatedUser(t, f, "user-x", "honestsky")

	_, err := f.svc.LoginWithDingTalk(context.Background(), "code", "https://kb.example.com/login")
	require.ErrorIs(t, err, ErrDingTalkUnknownIdentity)
}
