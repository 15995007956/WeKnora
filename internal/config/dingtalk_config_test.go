package config

import (
	"strings"
	"testing"
)

// TestDingTalkEnvOverrides verifies every DINGTALK_* variable reaches the
// config section, since operators enable corporate SSO through .env only.
func TestDingTalkEnvOverrides(t *testing.T) {
	t.Setenv("DINGTALK_AUTH_ENABLE", "true")
	t.Setenv("DINGTALK_APP_KEY", "app-key")
	t.Setenv("DINGTALK_APP_SECRET", "app-secret")
	t.Setenv("DINGTALK_CORP_ID", "corp-1")
	t.Setenv("DINGTALK_PROVIDER_DISPLAY_NAME", "DingTalk SSO")
	t.Setenv("DINGTALK_PROVISIONING_MODE", DingTalkProvisioningTenantless)
	t.Setenv("DINGTALK_BIND_BY_EMAIL", "true")

	cfg := &Config{}
	applyDingTalkEnvOverrides(cfg)

	d := cfg.DingTalkAuth
	if d == nil {
		t.Fatal("DingTalkAuth section was not created")
	}
	if !d.Enable || d.AppKey != "app-key" || d.AppSecret != "app-secret" {
		t.Fatalf("credentials were not applied: %+v", d)
	}
	if d.CorpID != "corp-1" {
		t.Fatalf("corp id = %q, want corp-1", d.CorpID)
	}
	if d.ProviderDisplayName != "DingTalk SSO" {
		t.Fatalf("display name = %q", d.ProviderDisplayName)
	}
	if d.ProvisioningMode != DingTalkProvisioningTenantless {
		t.Fatalf("provisioning mode = %q", d.ProvisioningMode)
	}
	if !d.BindByEmail {
		t.Fatal("bind_by_email override was not applied")
	}
}

// TestDingTalkDefaults verifies the DingTalk public endpoints and defaults are
// filled in when the operator only supplies credentials.
func TestDingTalkDefaults(t *testing.T) {
	cfg := &Config{}
	applyDingTalkEnvOverrides(cfg)

	d := cfg.DingTalkAuth
	if d.AuthorizeEndpoint != DefaultDingTalkAuthorizeEndpoint {
		t.Fatalf("authorize endpoint = %q", d.AuthorizeEndpoint)
	}
	if d.TokenEndpoint != DefaultDingTalkTokenEndpoint {
		t.Fatalf("token endpoint = %q", d.TokenEndpoint)
	}
	if d.UserInfoEndpoint != DefaultDingTalkUserInfoEndpoint {
		t.Fatalf("userinfo endpoint = %q", d.UserInfoEndpoint)
	}
	if d.ProviderDisplayName != DefaultDingTalkDisplayName {
		t.Fatalf("display name = %q", d.ProviderDisplayName)
	}
	if d.ProvisioningMode != DingTalkProvisioningCreatePersonal {
		t.Fatalf("provisioning mode = %q", d.ProvisioningMode)
	}
	if d.Enabled() {
		t.Fatal("DingTalk must stay disabled until enable and credentials are all set")
	}
}

// TestDingTalkClientIDAlias verifies the CLIENT_ID/CLIENT_SECRET spellings
// work, since the OAuth2 wire fields are clientId/clientSecret and operators
// commonly use those names.
func TestDingTalkClientIDAlias(t *testing.T) {
	t.Setenv("DINGTALK_AUTH_ENABLE", "true")
	t.Setenv("DINGTALK_CLIENT_ID", "alias-key")
	t.Setenv("DINGTALK_CLIENT_SECRET", "alias-secret")

	cfg := &Config{}
	applyDingTalkEnvOverrides(cfg)

	if cfg.DingTalkAuth.AppKey != "alias-key" {
		t.Fatalf("app key = %q, want alias-key", cfg.DingTalkAuth.AppKey)
	}
	if cfg.DingTalkAuth.AppSecret != "alias-secret" {
		t.Fatalf("app secret not read from DINGTALK_CLIENT_SECRET")
	}
	if !cfg.DingTalkAuth.Enabled() {
		t.Fatal("aliased credentials must enable DingTalk")
	}
}

// TestDingTalkAppKeyWinsOverAlias pins the precedence when both names are set.
func TestDingTalkAppKeyWinsOverAlias(t *testing.T) {
	t.Setenv("DINGTALK_APP_KEY", "canonical")
	t.Setenv("DINGTALK_CLIENT_ID", "alias")
	t.Setenv("DINGTALK_APP_SECRET", "canonical-secret")
	t.Setenv("DINGTALK_CLIENT_SECRET", "alias-secret")

	cfg := &Config{}
	applyDingTalkEnvOverrides(cfg)

	if cfg.DingTalkAuth.AppKey != "canonical" {
		t.Fatalf("app key = %q, want canonical", cfg.DingTalkAuth.AppKey)
	}
	if cfg.DingTalkAuth.AppSecret != "canonical-secret" {
		t.Fatalf("app secret = %q, want canonical-secret", cfg.DingTalkAuth.AppSecret)
	}
}

// TestDingTalkDisabledByMissingCredentials pins the fail-safe: enable alone is
// not enough, so a half-configured deployment does not expose a broken button.
func TestDingTalkDisabledByMissingCredentials(t *testing.T) {
	cfg := &Config{DingTalkAuth: &DingTalkAuthConfig{Enable: true, AppKey: "k"}}
	if cfg.DingTalkAuth.Enabled() {
		t.Fatal("missing app_secret must keep DingTalk disabled")
	}
	cfg.DingTalkAuth.AppSecret = "s"
	if !cfg.DingTalkAuth.Enabled() {
		t.Fatal("complete credentials must enable DingTalk")
	}
}

// TestValidateConfigRejectsIncompleteDingTalk covers the startup guard.
func TestValidateConfigRejectsIncompleteDingTalk(t *testing.T) {
	cfg := &Config{DingTalkAuth: &DingTalkAuthConfig{Enable: true}}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected a validation error for missing DingTalk credentials")
	}
	if !strings.Contains(err.Error(), "dingtalk_auth.app_key") {
		t.Fatalf("error should name the missing key, got: %v", err)
	}
}

// TestValidateConfigRejectsUnknownDingTalkProvisioningMode guards the enum.
func TestValidateConfigRejectsUnknownDingTalkProvisioningMode(t *testing.T) {
	cfg := &Config{DingTalkAuth: &DingTalkAuthConfig{
		Enable:           true,
		AppKey:           "k",
		AppSecret:        "s",
		ProvisioningMode: "sometimes",
	}}
	err := ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "provisioning_mode") {
		t.Fatalf("expected a provisioning_mode validation error, got: %v", err)
	}
}

// TestValidateConfigAcceptsValidDingTalk confirms a complete block passes.
func TestValidateConfigAcceptsValidDingTalk(t *testing.T) {
	for _, mode := range []string{
		DingTalkProvisioningCreatePersonal,
		DingTalkProvisioningTenantless,
		DingTalkProvisioningDeny,
		"",
	} {
		cfg := &Config{DingTalkAuth: &DingTalkAuthConfig{
			Enable:           true,
			AppKey:           "k",
			AppSecret:        "s",
			ProvisioningMode: mode,
		}}
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("mode %q should validate, got: %v", mode, err)
		}
	}
}
