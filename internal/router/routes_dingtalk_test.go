package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Tencent/WeKnora/internal/config"
	"github.com/Tencent/WeKnora/internal/handler"
)

// TestDingTalkAuthRoutesAreRegistered pins the public entry points of the
// DingTalk login flow. They must stay unauthenticated (logging in is the whole
// point) and must therefore never be gated by an API-key policy.
func TestDingTalkAuthRoutesAreRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	g := &rbacGuards{}

	// A real AuthHandler with nil services: the assertions below only need the
	// routes to exist and the public config endpoint to answer, neither of
	// which dereferences a service.
	authHandler := handler.NewAuthHandler(&config.Config{}, nil, nil, nil, nil)

	RegisterAuthRoutes(engine.Group("/api/v1"), authHandler, g)

	routes := map[string]bool{}
	for _, info := range engine.Routes() {
		routes[info.Method+" "+info.Path] = true
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/dingtalk/config"},
		{http.MethodGet, "/api/v1/auth/dingtalk/url"},
		{http.MethodGet, "/api/v1/auth/dingtalk/start"},
		{http.MethodGet, "/api/v1/auth/dingtalk/callback"},
	} {
		assert.Truef(t, routes[tc.method+" "+tc.path], "route %s %s must be registered", tc.method, tc.path)
	}

	// The public config endpoint must answer without any credential, since
	// the login page calls it before the user exists as a session.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/dingtalk/config", nil)
	engine.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"enabled"`)

	// No API-key policy may have been declared for these routes, so the
	// startup self-check must still be satisfied.
	require.NotPanics(t, func() { g.assertAPIKeyPoliciesMatchRoutes(engine) })
}
