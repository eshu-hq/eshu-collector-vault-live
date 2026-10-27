// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	sdktransport "github.com/eshu-hq/eshu-sdk/collector/transport"
)

// defaultRetryAfterSeconds bounds the host backoff when upstream gives no
// Retry-After guidance. The SDK requires a positive retry_after_seconds on
// retryable failure statuses, so a missing header cannot mean zero.
const defaultRetryAfterSeconds = 60

// Handler failure classes. They name the failure in operator status rows and
// never carry upstream bodies, URLs, or credentials.
const (
	// FailureInvalidConfig marks a claim whose activation config is missing or
	// malformed. It is terminal: retrying the same config cannot succeed.
	FailureInvalidConfig = "invalid_config"
	// FailureUnknownScope marks a claim scope no configured target covers. It
	// is retryable: the coordinator may configure it later, and a tight
	// terminal loop must not spin on it.
	FailureUnknownScope = "unknown_scope"
)

// sourceErrorClass values classify collect-time failures for the handler.
const (
	errorClassRetryable    = "retryable"
	errorClassNonRetryable = "non_retryable"
	errorClassRateLimited  = "rate_limited"
)

// Handler runs one SDK claim. The zero value is usable: it reads the process
// environment, the wall clock, and the live Vault HTTPS API.
type Handler struct {
	// Getenv resolves credential environment variables; nil selects os.Getenv,
	// so the zero value reads the process environment.
	Getenv func(string) string
	// Now supplies the clock; nil selects time.Now.
	Now func() time.Time
	// Log receives one bounded JSON diagnostic line per claim; nil discards
	// it. The binary points it at stderr, which the extension host's process
	// runner does not surface (it keeps only a byte count), so the line helps
	// a local run and a test, not an operator in production.
	Log io.Writer
	// NewCollector builds the collection source; nil uses NewCollector. Tests
	// stub it to inject a fake without HTTP.
	NewCollector func(SourceConfig) (*Collector, error)
}

func (h Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h Handler) getenv(key string) string {
	if h.Getenv != nil {
		return h.Getenv(key)
	}
	return os.Getenv(key)
}

func (h Handler) newCollector(config SourceConfig) (*Collector, error) {
	if h.NewCollector != nil {
		return h.NewCollector(config)
	}
	return NewCollector(config)
}

// Handle collects the Vault target named by the claim and returns the SDK
// result the host validates and commits. It never returns facts together with
// a failure state, never lets a credential into a result, and echoes the
// claim unchanged so the host's identity check passes.
func (h Handler) Handle(ctx context.Context, request sdk.Request) (sdk.Result, error) {
	started := h.now()
	claim := request.Claim
	if strings.TrimSpace(claim.CollectorKind) != CollectorKind {
		return sdk.Result{}, fmt.Errorf("claim.collector_kind %q is not %q", claim.CollectorKind, CollectorKind)
	}
	if sourceSystem := strings.TrimSpace(claim.SourceSystem); sourceSystem != "" && sourceSystem != CollectorKind {
		return sdk.Result{}, fmt.Errorf("claim.source_system %q is not %q", claim.SourceSystem, CollectorKind)
	}
	fence, err := parseFencingToken(claim.FencingToken)
	if err != nil {
		return sdk.Result{}, err
	}
	settings, err := ParseSettings(request.Config, h.getenv)
	if err != nil {
		// Parse errors name config keys only and never quote a configured
		// value, so they are safe for the diagnostic log line.
		h.logLine(map[string]any{
			"event": "config_failure", "scope": claim.Scope.ID,
			"generation": claim.GenerationID, "class": FailureInvalidConfig,
		})
		return terminalResult(claim, started, failureStatus(FailureInvalidConfig, 0, elapsedMS(started, h.now()))), nil
	}
	collector, err := h.newCollector(settings.Source)
	if err != nil {
		h.logLine(map[string]any{
			"event": "config_failure", "scope": claim.Scope.ID,
			"generation": claim.GenerationID, "class": FailureInvalidConfig,
		})
		return terminalResult(claim, started, failureStatus(FailureInvalidConfig, 0, elapsedMS(started, h.now()))), nil
	}
	target, err := collector.ResolveTarget(claim.Scope.ID)
	if err != nil {
		h.logLine(map[string]any{
			"event": "unknown_scope", "scope": claim.Scope.ID,
			"generation": claim.GenerationID, "class": FailureUnknownScope,
		})
		return retryableResult(
			claim,
			started,
			failureStatus(FailureUnknownScope, defaultRetryAfterSeconds, elapsedMS(started, h.now())),
		), nil
	}
	boundary := Boundary{
		ScopeID:             target.ScopeID,
		GenerationID:        claim.GenerationID,
		CollectorInstanceID: settings.Source.CollectorInstanceID,
		FencingToken:        fence,
		ObservedAt:          started,
		SourceSystem:        claim.SourceSystem,
	}
	facts, observedAt, err := collector.Collect(ctx, target, boundary)
	if err != nil {
		return h.failureResult(claim, started, target, err), nil
	}
	if observedAt.IsZero() {
		observedAt = h.now()
	}
	freshnessHint := "complete"
	if hasCoverageWarning(facts) {
		freshnessHint = "partial"
	}
	latency := elapsedMS(started, h.now())
	h.logLine(map[string]any{
		"event": "complete", "scope": target.ScopeID,
		"generation": claim.GenerationID, "facts": len(facts), "latency_ms": latency,
		"freshness": freshnessHint,
	})
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim:           claim,
		Generation: sdk.Generation{
			ID:            claim.GenerationID,
			ObservedAt:    observedAt.UTC(),
			FreshnessHint: freshnessHint,
		},
		Facts: facts,
		Statuses: []sdk.Status{{
			Class:           sdk.StatusComplete,
			FactCount:       len(facts),
			SourceLatencyMS: latency,
		}},
	}, nil
}

// parseFencingToken validates the claim fencing token before any client call:
// it must be a positive integer generation counter, mirroring the in-tree
// admission that rejects a missing fence before the client factory runs.
func parseFencingToken(raw string) (int64, error) {
	fence, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || fence <= 0 {
		return 0, fmt.Errorf("claim.fencing_token must be a positive integer generation counter")
	}
	return fence, nil
}

func (h Handler) failureResult(
	claim sdk.Claim,
	started time.Time,
	target TargetConfig,
	err error,
) sdk.Result {
	classified := classifiedSourceFailure(err)
	class := sourceErrorClass(classified)
	latency := elapsedMS(started, h.now())
	h.logLine(map[string]any{
		"event": "failure", "scope": target.ScopeID,
		"generation": claim.GenerationID, "class": class,
		"http_status": responseStatusCode(classified), "latency_ms": latency,
		"result": requestResult(classified),
	})
	if class == errorClassNonRetryable {
		return terminalResult(claim, started, failureStatus(class, 0, latency))
	}
	return retryableResult(claim, started, failureStatus(class, retryAfterSeconds(classified), latency))
}

// configValidationError marks a static misconfiguration as terminal: retrying
// the same input cannot succeed.
type configValidationError struct {
	err error
}

func (e configValidationError) Error() string { return e.err.Error() }

func (e configValidationError) Unwrap() error { return e.err }

func sourceErrorClass(err error) string {
	if err == nil {
		return ""
	}
	var configErr configValidationError
	var mappingErr vaultMappingError
	if errors.As(err, &configErr) || errors.As(err, &mappingErr) {
		return errorClassNonRetryable
	}
	code := responseStatusCode(err)
	switch {
	case code == http.StatusTooManyRequests:
		return errorClassRateLimited
	case code >= 400 && code < 500 && code != http.StatusRequestTimeout:
		return errorClassNonRetryable
	default:
		return errorClassRetryable
	}
}

func classifiedSourceFailure(err error) error {
	if err == nil {
		return nil
	}
	class := sourceErrorClass(err)
	return sourceFailure{
		err:      err,
		class:    class,
		terminal: class == errorClassNonRetryable,
	}
}

type sourceFailure struct {
	err      error
	class    string
	terminal bool
}

func (e sourceFailure) Error() string { return e.err.Error() }

func (e sourceFailure) Unwrap() error { return e.err }

func (e sourceFailure) FailureClass() string { return e.class }

func (e sourceFailure) TerminalFailure() bool { return e.terminal }

func responseStatusCode(err error) int {
	var httpErr sdktransport.HTTPError
	if !errors.As(err, &httpErr) {
		return 0
	}
	return httpErr.StatusCode
}

// requestResult classifies a collect error for operator status rows:
// throttling stays distinct from terminal failure.
func requestResult(err error) string {
	if err == nil {
		return "success"
	}
	var httpErr sdktransport.HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusTooManyRequests {
		return "rate_limited"
	}
	return "error"
}

// retryAfterSeconds prefers upstream Retry-After guidance and falls back to
// the bounded default so retryable statuses always validate.
func retryAfterSeconds(err error) int {
	var httpErr sdktransport.HTTPError
	if errors.As(err, &httpErr) && httpErr.RetryAfterDelay() > 0 {
		if seconds := int(httpErr.RetryAfterDelay().Seconds()); seconds > 0 {
			return seconds
		}
	}
	return defaultRetryAfterSeconds
}

func terminalResult(claim sdk.Claim, observedAt time.Time, status sdk.Status) sdk.Result {
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultTerminal,
		Claim:           claim,
		Generation: sdk.Generation{
			ID:         claim.GenerationID,
			ObservedAt: observedAt.UTC(),
		},
		Statuses: []sdk.Status{status},
	}
}

func retryableResult(claim sdk.Claim, observedAt time.Time, status sdk.Status) sdk.Result {
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultRetryable,
		Claim:           claim,
		Generation: sdk.Generation{
			ID:         claim.GenerationID,
			ObservedAt: observedAt.UTC(),
		},
		Statuses: []sdk.Status{status},
	}
}

func failureStatus(class string, retryAfterSeconds, latencyMS int) sdk.Status {
	return sdk.Status{
		Class:             sdk.StatusFailure,
		FailureClass:      class,
		RetryAfterSeconds: retryAfterSeconds,
		SourceLatencyMS:   latencyMS,
	}
}

func elapsedMS(started, now time.Time) int {
	if ms := int(now.Sub(started).Milliseconds()); ms >= 0 {
		return ms
	}
	return 0
}

func (h Handler) logLine(fields map[string]any) {
	if h.Log == nil {
		return
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return
	}
	_, _ = io.WriteString(h.Log, string(raw)+"\n")
}
