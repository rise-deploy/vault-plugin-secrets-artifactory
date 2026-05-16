package artifactory

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeOverrideMode_ParseAndJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  interface{}
		want scopeOverrideMode
	}{
		{name: "nil", raw: nil, want: scopeOverrideDisabled},
		{name: "empty", raw: "", want: scopeOverrideDisabled},
		{name: "disabled", raw: "disabled", want: scopeOverrideDisabled},
		{name: "false bool", raw: false, want: scopeOverrideDisabled},
		{name: "false string", raw: "false", want: scopeOverrideDisabled},
		{name: "zero string", raw: "0", want: scopeOverrideDisabled},
		{name: "global", raw: "global", want: scopeOverrideGlobal},
		{name: "true bool", raw: true, want: scopeOverrideGlobal},
		{name: "true string", raw: "true", want: scopeOverrideGlobal},
		{name: "one string", raw: "1", want: scopeOverrideGlobal},
		{name: "opt-in", raw: "opt-in", want: scopeOverrideOptIn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseScopeOverrideMode(tt.raw)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	var fromBool scopeOverrideMode
	require.NoError(t, json.Unmarshal([]byte(`true`), &fromBool))
	assert.Equal(t, scopeOverrideGlobal, fromBool)

	var fromString scopeOverrideMode
	require.NoError(t, json.Unmarshal([]byte(`"opt-in"`), &fromString))
	assert.Equal(t, scopeOverrideOptIn, fromString)
}

func TestScopeGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		scope   string
		want    bool
	}{
		{pattern: "artifact:**", scope: "artifact:path/more:r,w", want: false},
		{pattern: "artifact:**:r,w", scope: "artifact:path/more:r,w", want: true},
		{pattern: "artifact:*:r,w", scope: "artifact:path:r,w", want: true},
		{pattern: "artifact:*:r,w", scope: "artifact:path/more:r,w", want: false},
		{pattern: "artifact:repo/path/++:r,w", scope: "artifact:repo/path/team/app:r,w", want: true},
		{pattern: "artifact:repo/path/++:r,w", scope: "artifact:repo/path/*:r,w", want: false},
		{pattern: "artifact:repo/path/++:r,w", scope: "artifact:repo/path/**:r,w", want: false},
		{pattern: "applied-permissions/groups:*", scope: "applied-permissions/groups:test", want: true},
		{pattern: "applied-permissions/groups:*", scope: "applied-permissions/groups:test/child", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+" "+tt.scope, func(t *testing.T) {
			got, err := scopeGlobMatch(tt.pattern, tt.scope)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateScopeOverride_MultiScope(t *testing.T) {
	allowedScopes := []string{
		"artifact:repo/path/++:r,w",
		"applied-permissions/groups:*",
	}

	err := validateScopeOverride("artifact:repo/path/team/app:r,w applied-permissions/groups:readers", allowedScopes)
	require.NoError(t, err)

	err = validateScopeOverride("artifact:repo/path/team/app:r,w member-of-groups:readers", allowedScopes)
	require.Error(t, err)
}

func TestBackend_PathConfigScopeOverrideSettings(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockArtifactoryUsageVersionRequests("")

	b, config := configuredBackend(t, map[string]interface{}{
		"access_token":           "test-access-token",
		"url":                    "http://myserver.com:80",
		"allow_scope_override":   "opt-in",
		"default_allowed_scopes": `["artifact:**:r,w"]`,
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configAdminPath,
		Storage:   config.StorageView,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, scopeOverrideOptIn, resp.Data["allow_scope_override"])
	assert.Equal(t, []string{"artifact:**:r,w"}, resp.Data["default_allowed_scopes"])
}

func TestBackend_PathRoleScopeOverrideSettings(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockArtifactoryUsageVersionRequests("")

	b, config := configuredBackend(t, map[string]interface{}{
		"access_token": "test-access-token",
		"url":          "http://myserver.com:80",
	})

	roleData := map[string]interface{}{
		"role":                 "test-role",
		"username":             "test-username",
		"scope":                "test-scope",
		"allow_scope_override": true,
		"allowed_scopes":       `["artifact:repo/path/++:r,w"]`,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   config.StorageView,
		Data:      roleData,
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-role",
		Storage:   config.StorageView,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, true, resp.Data["allow_scope_override"])
	assert.Equal(t, []string{"artifact:repo/path/++:r,w"}, resp.Data["allowed_scopes"])
}

func TestBackend_PathConfigUserTokenScopeOverrideSettings(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockArtifactoryUsageVersionRequests("")

	b, config := configuredBackend(t, map[string]interface{}{
		"access_token": "test-access-token",
		"url":          "http://myserver.com:80",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configUserTokenPath + "/test-user",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"allow_scope_override": true,
			"allowed_scopes":       `["artifact:repo/path/++:r,w"]`,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	userTokenConfig, err := b.fetchUserTokenConfiguration(context.Background(), config.StorageView, "test-user")
	require.NoError(t, err)
	require.NotNil(t, userTokenConfig)

	assert.Equal(t, true, userTokenConfig.AllowScopeOverride)
	assert.Equal(t, []string{"artifact:repo/path/++:r,w"}, userTokenConfig.AllowedScopes)
}

func TestBackend_ScopeOverridePolicyForRoleTokens(t *testing.T) {
	tests := []struct {
		name        string
		adminData   map[string]interface{}
		roleData    map[string]interface{}
		scope       string
		wantAllowed bool
	}{
		{
			name: "disabled denies even when role opts in",
			adminData: map[string]interface{}{
				"access_token": "test-access-token",
				"url":          "http://myserver.com:80",
			},
			roleData: map[string]interface{}{
				"allow_scope_override": true,
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: false,
		},
		{
			name: "legacy true maps to global and default allowlist permits groups",
			adminData: map[string]interface{}{
				"access_token":         "test-access-token",
				"url":                  "http://myserver.com:80",
				"allow_scope_override": true,
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: true,
		},
		{
			name: "global default allowlist permits artifact scopes when configured",
			adminData: map[string]interface{}{
				"access_token":           "test-access-token",
				"url":                    "http://myserver.com:80",
				"allow_scope_override":   "global",
				"default_allowed_scopes": `["artifact:**:r,w"]`,
			},
			scope:       "artifact:repo/path:r,w",
			wantAllowed: true,
		},
		{
			name: "opt-in denies without role opt-in",
			adminData: map[string]interface{}{
				"access_token":         "test-access-token",
				"url":                  "http://myserver.com:80",
				"allow_scope_override": "opt-in",
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: false,
		},
		{
			name: "opt-in allows with role opt-in",
			adminData: map[string]interface{}{
				"access_token":         "test-access-token",
				"url":                  "http://myserver.com:80",
				"allow_scope_override": "opt-in",
			},
			roleData: map[string]interface{}{
				"allow_scope_override": true,
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: true,
		},
		{
			name: "role allowlist overrides global default",
			adminData: map[string]interface{}{
				"access_token":         "test-access-token",
				"url":                  "http://myserver.com:80",
				"allow_scope_override": "global",
			},
			roleData: map[string]interface{}{
				"allowed_scopes": `["artifact:**:r,w"]`,
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			mockArtifactoryUsageVersionRequests("")
			httpmock.RegisterResponder(
				http.MethodPost,
				"http://myserver.com:80/artifactory/api/security/token",
				httpmock.NewStringResponder(200, canonicalAccessToken))

			b, config := configuredBackend(t, tt.adminData)
			roleData := map[string]interface{}{
				"role":     "test-role",
				"username": "test-username",
				"scope":    "test-scope",
			}
			for k, v := range tt.roleData {
				roleData[k] = v
			}

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "roles/test-role",
				Storage:   config.StorageView,
				Data:      roleData,
			})
			require.NoError(t, err)
			require.Nil(t, resp)

			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "token/test-role",
				Storage:   config.StorageView,
				Data: map[string]interface{}{
					"scope": tt.scope,
				},
			})

			if tt.wantAllowed {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.False(t, resp.IsError())
				return
			}

			require.Error(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.IsError())
		})
	}
}

func TestBackend_ScopeOverridePolicyForUserTokens(t *testing.T) {
	tests := []struct {
		name           string
		adminData      map[string]interface{}
		userConfigData map[string]interface{}
		scope          string
		wantAllowed    bool
	}{
		{
			name: "disabled denies even when user config opts in",
			adminData: map[string]interface{}{
				"access_token": "test-access-token",
				"url":          "http://myserver.com:80",
			},
			userConfigData: map[string]interface{}{
				"allow_scope_override": true,
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: false,
		},
		{
			name: "global permits default group allowlist",
			adminData: map[string]interface{}{
				"access_token":         "test-access-token",
				"url":                  "http://myserver.com:80",
				"allow_scope_override": "global",
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: true,
		},
		{
			name: "opt-in requires user config opt-in",
			adminData: map[string]interface{}{
				"access_token":         "test-access-token",
				"url":                  "http://myserver.com:80",
				"allow_scope_override": "opt-in",
			},
			scope:       "applied-permissions/groups:test",
			wantAllowed: false,
		},
		{
			name: "opt-in allows user config opt-in with artifact allowlist",
			adminData: map[string]interface{}{
				"access_token":         "test-access-token",
				"url":                  "http://myserver.com:80",
				"allow_scope_override": "opt-in",
			},
			userConfigData: map[string]interface{}{
				"allow_scope_override": true,
				"allowed_scopes":       `["artifact:**:r,w"]`,
			},
			scope:       "artifact:repo/path:r,w",
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			mockArtifactoryUsageVersionRequests("")
			mockArtifactoryTokenRequest()
			httpmock.RegisterResponder(
				http.MethodPost,
				"http://myserver.com:80/artifactory/api/security/token",
				httpmock.NewStringResponder(200, canonicalAccessToken))

			b, config := configuredBackend(t, tt.adminData)
			if len(tt.userConfigData) > 0 {
				resp, err := b.HandleRequest(context.Background(), &logical.Request{
					Operation: logical.UpdateOperation,
					Path:      configUserTokenPath + "/test-user",
					Storage:   config.StorageView,
					Data:      tt.userConfigData,
				})
				require.NoError(t, err)
				require.Nil(t, resp)
			}

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      createUserTokenPath + "test-user",
				Storage:   config.StorageView,
				Data: map[string]interface{}{
					"scope": tt.scope,
				},
			})

			if tt.wantAllowed {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.False(t, resp.IsError())
				return
			}

			require.Error(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.IsError())
		})
	}
}
