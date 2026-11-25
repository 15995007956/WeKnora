package middleware

import "testing"

// TestDingTalkAuthRoutesAreAnonymous pins the global Auth middleware's
// exemption list for the DingTalk login flow.
//
// Every one of these endpoints is reached by a browser that has no WeKnora
// session yet: the login page probes /config, /url hands back the provider
// authorization URL, /start redirects straight to DingTalk, and /callback is
// the provider's own redirect. Missing any of them makes the login page show
// "Unauthorized: missing authentication" instead of the DingTalk button.
func TestDingTalkAuthRoutesAreAnonymous(t *testing.T) {
	paths := []string{
		"/api/v1/auth/dingtalk/config",
		"/api/v1/auth/dingtalk/url",
		"/api/v1/auth/dingtalk/start",
		"/api/v1/auth/dingtalk/callback",
	}
	for _, path := range paths {
		if !isNoAuthAPI(path, "GET") {
			t.Errorf("%s GET must bypass the global auth middleware", path)
		}
	}
}

// TestDingTalkRoutesRejectOtherMethods guards against an over-broad exemption:
// only GET is public, matching the route registrations.
func TestDingTalkRoutesRejectOtherMethods(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		if isNoAuthAPI("/api/v1/auth/dingtalk/config", method) {
			t.Errorf("%s on the DingTalk config route must still require auth", method)
		}
	}
}

// TestOIDCRoutesRemainAnonymous is a regression guard: the DingTalk addition
// must not have disturbed the OIDC exemptions it sits next to.
func TestOIDCRoutesRemainAnonymous(t *testing.T) {
	for _, path := range []string{
		"/api/v1/auth/oidc/config",
		"/api/v1/auth/oidc/url",
		"/api/v1/auth/oidc/start",
		"/api/v1/auth/oidc/callback",
	} {
		if !isNoAuthAPI(path, "GET") {
			t.Errorf("%s GET must stay anonymous", path)
		}
	}
}
