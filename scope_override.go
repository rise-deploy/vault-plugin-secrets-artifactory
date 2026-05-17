package artifactory

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	scopeOverrideDisabled scopeOverrideMode = "disabled"
	scopeOverrideGlobal   scopeOverrideMode = "global"
	scopeOverrideOptIn    scopeOverrideMode = "opt-in"
)

var defaultAllowedScopes = []string{"applied-permissions/groups:*"}

type scopeOverrideMode string

func parseScopeOverrideMode(raw interface{}) (scopeOverrideMode, error) {
	switch v := raw.(type) {
	case nil:
		return scopeOverrideDisabled, nil
	case bool:
		if v {
			return scopeOverrideGlobal, nil
		}
		return scopeOverrideDisabled, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "0", "false", "disabled":
			return scopeOverrideDisabled, nil
		case "1", "true", "global":
			return scopeOverrideGlobal, nil
		case "opt-in":
			return scopeOverrideOptIn, nil
		default:
			return "", fmt.Errorf("invalid allow_scope_override value %q", v)
		}
	default:
		return "", fmt.Errorf("invalid allow_scope_override type %T", raw)
	}
}

// MarshalJSON writes disabled/global as JSON booleans (false/true) to preserve
// rollback compatibility with older plugin versions that stored allow_scope_override
// as a bool. opt-in is a new capability and is written as a string; rolling back
// after configuring opt-in requires manual storage repair.
func (m scopeOverrideMode) MarshalJSON() ([]byte, error) {
	switch m {
	case scopeOverrideGlobal:
		return json.Marshal(true)
	case scopeOverrideDisabled, "":
		return json.Marshal(false)
	default: // scopeOverrideOptIn and any future modes
		return json.Marshal(string(m))
	}
}

// UnmarshalJSON accepts both the legacy boolean storage format and the current
// string format so that config written by older plugin versions decodes correctly.
func (m *scopeOverrideMode) UnmarshalJSON(data []byte) error {
	var boolValue bool
	if err := json.Unmarshal(data, &boolValue); err == nil {
		mode, err := parseScopeOverrideMode(boolValue)
		if err != nil {
			return err
		}
		*m = mode
		return nil
	}

	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err == nil {
		mode, err := parseScopeOverrideMode(stringValue)
		if err != nil {
			return err
		}
		*m = mode
		return nil
	}

	return errors.New("allow_scope_override must be a boolean or string")
}

func parseAllowedScopes(fieldName string, raw interface{}) ([]string, error) {
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, nil
		}
		var scopes []string
		if err := json.Unmarshal([]byte(v), &scopes); err != nil {
			return nil, fmt.Errorf("%s must be a JSON array of strings: %w", fieldName, err)
		}
		return scopes, nil
	case []string:
		return v, nil
	case []interface{}:
		scopes := make([]string, 0, len(v))
		for _, rawScope := range v {
			scope, ok := rawScope.(string)
			if !ok {
				return nil, fmt.Errorf("%s entries must be strings, got %T", fieldName, rawScope)
			}
			scopes = append(scopes, scope)
		}
		return scopes, nil
	default:
		return nil, fmt.Errorf("%s must be a JSON array of strings, got %T", fieldName, raw)
	}
}

func (c adminConfiguration) scopeOverrideMode() scopeOverrideMode {
	if c.AllowScopeOverride == "" {
		return scopeOverrideDisabled
	}
	return c.AllowScopeOverride
}

func (c adminConfiguration) effectiveDefaultAllowedScopes() []string {
	if c.DefaultAllowedScopes != nil {
		return c.DefaultAllowedScopes
	}
	return append([]string(nil), defaultAllowedScopes...)
}

func validateScopeOverride(scope string, allowedScopes []string) error {
	scopeEntries := strings.Fields(scope)
	if len(scopeEntries) == 0 {
		return errors.New("provided scope is invalid")
	}
	if len(allowedScopes) == 0 {
		return errors.New("scope override denied by allowlist policy")
	}

	for _, scopeEntry := range scopeEntries {
		matched := false
		for _, allowedScope := range allowedScopes {
			ok, err := scopeGlobMatch(allowedScope, scopeEntry)
			if err != nil {
				return err
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("scope %q is not allowed", scopeEntry)
		}
	}

	return nil
}

func scopeGlobMatch(pattern, scope string) (bool, error) {
	regexPattern := strings.Builder{}
	regexPattern.WriteString("^")

	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				regexPattern.WriteString("[^:]*")
				i += 2
			} else {
				regexPattern.WriteString("[^/:]*")
				i++
			}
		case '+':
			if i+1 < len(pattern) && pattern[i+1] == '+' {
				regexPattern.WriteString("[^:*]*")
				i += 2
			} else {
				regexPattern.WriteString("[^/:*]*")
				i++
			}
		default:
			regexPattern.WriteString(regexp.QuoteMeta(string(pattern[i])))
			i++
		}
	}

	regexPattern.WriteString("$")
	return regexp.MatchString(regexPattern.String(), scope)
}

func (c adminConfiguration) authorizeScopeOverride(scope string, enabled bool, allowedScopes []string) error {
	switch c.scopeOverrideMode() {
	case scopeOverrideDisabled:
		return errors.New("scope override is disabled")
	case scopeOverrideGlobal:
	case scopeOverrideOptIn:
		if !enabled {
			return errors.New("scope override is not enabled")
		}
	default:
		return fmt.Errorf("invalid allow_scope_override value %q", c.AllowScopeOverride)
	}

	effectiveAllowedScopes := allowedScopes
	if effectiveAllowedScopes == nil {
		effectiveAllowedScopes = c.effectiveDefaultAllowedScopes()
	}

	return validateScopeOverride(scope, effectiveAllowedScopes)
}
