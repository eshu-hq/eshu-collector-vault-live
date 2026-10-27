// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"os"
	"strings"
)

// envRedactionKey names the environment variable holding the deployment-scoped
// HMAC redaction key. The name matches the in-tree command so existing
// deployments keep working; the value never appears in claim config, facts,
// logs, or docs.
const envRedactionKey = "ESHU_VAULT_LIVE_REDACTION_KEY"

// Settings is the validated activation config for one claim: the redaction
// key plus the standalone source the Collector runs. Credential material is
// resolved from the environment at call time into runtime-only fields: it
// never reaches facts, logs, metric labels, or docs.
type Settings struct {
	Key    redactionKey
	Source SourceConfig
}

// ParseSettings decodes the host-supplied config object into validated source
// settings. It accepts the JSON shapes command.Run produces (numbers arrive
// as json.Number) as well as plain decoded maps. Parse errors name config
// keys only and never quote a configured value, so they are safe for
// diagnostic logs.
func ParseSettings(config map[string]any, getenv func(string) string) (Settings, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	collectorID, err := configString(config, "collector_instance_id")
	if err != nil {
		return Settings{}, err
	}
	if strings.TrimSpace(collectorID) == "" {
		return Settings{}, fmt.Errorf("config: collector_instance_id is required")
	}
	key, err := loadRedactionKey(getenv)
	if err != nil {
		return Settings{}, err
	}
	targets, err := parseVaultTargets(config, getenv)
	if err != nil {
		return Settings{}, err
	}
	return Settings{Key: key, Source: SourceConfig{
		CollectorInstanceID: strings.TrimSpace(collectorID),
		Targets:             targets,
		Key:                 key,
	}}, nil
}

func loadRedactionKey(getenv func(string) string) (redactionKey, error) {
	raw := strings.TrimSpace(getenv(envRedactionKey))
	if raw == "" {
		return redactionKey{}, fmt.Errorf("config: %s is required", envRedactionKey)
	}
	key, err := newRedactionKey([]byte(raw))
	if err != nil {
		return redactionKey{}, fmt.Errorf("config: invalid %s", envRedactionKey)
	}
	return key, nil
}

// bannedConfigKeys carry secret material and must never appear in claim
// config: connection details and the read-only token live in the environment
// (token_env names the variable) and the command-local client factory. The
// sanctioned pointer token_env is the single exception.
var bannedConfigKeys = []string{"secret", "password", "credential", "api_key", "private_key"}

func parseVaultTargets(config map[string]any, getenv func(string) string) ([]TargetConfig, error) {
	raw, ok := config["targets"]
	if !ok || raw == nil {
		return nil, fmt.Errorf("config: targets must list at least one vault target")
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("config: targets must list at least one vault target")
	}
	targets := make([]TargetConfig, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	for i, item := range list {
		mapped, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("config: targets[%d] must be an object", i)
		}
		if err := rejectSecretKeys(i, mapped); err != nil {
			return nil, err
		}
		target, err := parseVaultTarget(i, mapped, getenv)
		if err != nil {
			return nil, err
		}
		key := authKey(target.VaultClusterID, target.Namespace)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("config: targets[%d]: duplicate vault target scope", i)
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}

// rejectSecretKeys enforces the no-token-in-config boundary: a target that
// names secret material inline fails closed. Only token_env — the pointer to
// the environment variable holding the read-only token — may appear. Errors
// name the offending key, never its value.
func rejectSecretKeys(index int, mapped map[string]any) error {
	for key := range mapped {
		lowered := strings.ToLower(strings.TrimSpace(key))
		if lowered == "token_env" {
			continue
		}
		// Any "*token*" key other than the sanctioned token_env pointer is a
		// secret in config. A future legitimate "*token*" key must be
		// deliberately allowlisted here, never silently admitted.
		if strings.Contains(lowered, "token") {
			return fmt.Errorf("config: targets[%d]: %q must not appear; name the env var with token_env", index, key)
		}
		for _, banned := range bannedConfigKeys {
			if strings.Contains(lowered, banned) {
				return fmt.Errorf("config: targets[%d]: %q must not appear; secrets resolve from the environment", index, key)
			}
		}
	}
	return nil
}

func parseVaultTarget(index int, mapped map[string]any, getenv func(string) string) (TargetConfig, error) {
	clusterID, err := configString(mapped, "vault_cluster_id")
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: vault_cluster_id must not be blank", index)
	}
	address, err := configString(mapped, "address")
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	if strings.TrimSpace(address) == "" {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: address must not be blank", index)
	}
	tokenEnv, err := configString(mapped, "token_env")
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	tokenEnv = strings.TrimSpace(tokenEnv)
	if tokenEnv == "" {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: token_env must name the env var holding the read-only token", index)
	}
	token := strings.TrimSpace(getenv(tokenEnv))
	if token == "" {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: env %s is empty", index, tokenEnv)
	}
	namespace, err := configString(mapped, "namespace")
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	displayName, err := configString(mapped, "display_name")
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	environment, err := configString(mapped, "environment")
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	sourceURI, err := configString(mapped, "source_uri")
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	scopeID, err := VaultScopeID(clusterID, strings.TrimSpace(namespace))
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: targets[%d]: %w", index, err)
	}
	return TargetConfig{
		VaultClusterID: clusterID,
		Namespace:      strings.TrimSpace(namespace),
		DisplayName:    strings.TrimSpace(displayName),
		Environment:    strings.TrimSpace(environment),
		SourceURI:      strings.TrimSpace(sourceURI),
		ScopeID:        scopeID,
		Address:        strings.TrimSpace(address),
		Token:          token,
	}, nil
}

func configString(raw map[string]any, key string) (string, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return "", nil
	}
	switch typed := value.(type) {
	case string:
		return typed, nil
	default:
		return "", fmt.Errorf("%s must be a string", key)
	}
}
