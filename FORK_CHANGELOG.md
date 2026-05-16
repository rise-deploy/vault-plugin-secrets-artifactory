# Fork Changelog

This file tracks changes carried by the Rise fork that differ from upstream
`jfrog/vault-plugin-secrets-artifactory`.

## Unreleased

### Fork Changes

* Expanded scope override controls beyond the upstream boolean:
  `disabled`/`false` denies overrides, `global`/`true` preserves the previous
  global behavior, and `opt-in` requires the role or user-token config to enable
  `allow_scope_override`.
* Added `allowed_scopes` to roles and user-token configuration, plus
  `default_allowed_scopes` on admin config. These JSON string arrays define
  glob-style allowlists for requested token `scope` overrides.
* Replaced the hardcoded group-scope-only validation with shared allowlist
  validation for both `token/:role` and `user_token/:username`. Scope entries
  are matched individually, with `*`/`**` not crossing `:` boundaries and
  `+`/`++` also refusing to match literal JFrog wildcard characters.

### Carried Upstream PRs

| Status | Upstream PR | Summary | Drop Condition |
| --- | --- | --- | --- |
| Carried | [jfrog/vault-plugin-secrets-artifactory#337](https://github.com/jfrog/vault-plugin-secrets-artifactory/pull/337) | Enforce `allow_scope_override` for `user_token/:username` scope overrides. | Remove from the fork delta after rebasing or merging an upstream release that includes this PR. |
