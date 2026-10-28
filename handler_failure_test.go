// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"errors"
	"fmt"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	sdktransport "github.com/eshu-hq/eshu-sdk/collector/transport"
)

func failureClaim() sdk.Claim {
	return sdk.Claim{GenerationID: "gen-1"}
}

func TestFailureResultTerminal(t *testing.T) {
	t.Parallel()
	h := Handler{}
	started := time.Now().Add(-time.Second)
	res := h.failureResult(failureClaim(), started, TargetConfig{ScopeID: "s"}, configValidationError{err: errors.New("bad")})
	if res.State != sdk.ResultTerminal {
		t.Fatalf("state = %v", res.State)
	}
	if len(res.Statuses) != 1 || res.Statuses[0].FailureClass != errorClassNonRetryable {
		t.Fatalf("statuses = %+v", res.Statuses)
	}
	if res.Statuses[0].RetryAfterSeconds != 0 {
		t.Fatalf("terminal must not retry: %+v", res.Statuses[0])
	}
}

func TestFailureResultRetryableAndRateLimited(t *testing.T) {
	t.Parallel()
	h := Handler{}
	started := time.Now().Add(-time.Second)
	retryable := h.failureResult(failureClaim(), started, TargetConfig{},
		fmt.Errorf("boom: %w", sdktransport.HTTPError{Provider: "vault", StatusCode: 500}))
	if retryable.State != sdk.ResultRetryable {
		t.Fatalf("state = %v", retryable.State)
	}
	if retryable.Statuses[0].RetryAfterSeconds != defaultRetryAfterSeconds {
		t.Fatalf("default backoff = %+v", retryable.Statuses[0])
	}
	limited := h.failureResult(failureClaim(), started, TargetConfig{},
		sdktransport.HTTPError{Provider: "vault", StatusCode: 429, RetryAfter: 90 * time.Second})
	if limited.State != sdk.ResultRetryable || limited.Statuses[0].FailureClass != errorClassRateLimited {
		t.Fatalf("limited = %+v", limited.Statuses)
	}
	if limited.Statuses[0].RetryAfterSeconds != 90 {
		t.Fatalf("upstream backoff = %+v", limited.Statuses[0])
	}
	bare := h.failureResult(failureClaim(), started, TargetConfig{},
		sdktransport.HTTPError{Provider: "vault", StatusCode: 429})
	if bare.Statuses[0].RetryAfterSeconds != defaultRetryAfterSeconds {
		t.Fatalf("missing header falls back: %+v", bare.Statuses[0])
	}
}

func TestSourceErrorClassMatrix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"config", configValidationError{err: errors.New("x")}, errorClassNonRetryable},
		{"mapping", vaultMappingError{err: errors.New("x")}, errorClassNonRetryable},
		{"wrapped mapping", fmt.Errorf("w: %w", vaultMappingError{err: errors.New("x")}), errorClassNonRetryable},
		{"rate limited", sdktransport.HTTPError{StatusCode: 429}, errorClassRateLimited},
		{"not found", sdktransport.HTTPError{StatusCode: 404}, errorClassNonRetryable},
		{"forbidden", sdktransport.HTTPError{StatusCode: 403}, errorClassNonRetryable},
		{"timeout retries", sdktransport.HTTPError{StatusCode: 408}, errorClassRetryable},
		{"server retries", sdktransport.HTTPError{StatusCode: 503}, errorClassRetryable},
		{"plain error retries", errors.New("dial"), errorClassRetryable},
	} {
		if got := sourceErrorClass(tc.err); got != tc.want {
			t.Errorf("%s: class = %q, want %q", tc.name, got, tc.want)
		}
		if classified := classifiedSourceFailure(tc.err); (classified == nil) != (tc.err == nil) {
			t.Errorf("%s: classified nil mismatch", tc.name)
		}
	}
}

func TestFailureClassifiers(t *testing.T) {
	t.Parallel()
	if got := requestResult(nil); got != "success" {
		t.Fatalf("nil = %q", got)
	}
	if got := requestResult(sdktransport.HTTPError{StatusCode: 429}); got != "rate_limited" {
		t.Fatalf("429 = %q", got)
	}
	if got := requestResult(errors.New("x")); got != "error" {
		t.Fatalf("plain = %q", got)
	}
	if got := responseStatusCode(nil); got != 0 {
		t.Fatalf("nil = %d", got)
	}
	if got := responseStatusCode(errors.New("x")); got != 0 {
		t.Fatalf("plain = %d", got)
	}
	if got := responseStatusCode(sdktransport.HTTPError{StatusCode: 503}); got != 503 {
		t.Fatalf("status = %d", got)
	}
	if got := retryAfterSeconds(nil); got != defaultRetryAfterSeconds {
		t.Fatalf("nil backoff = %d", got)
	}
	if got := retryAfterSeconds(sdktransport.HTTPError{RetryAfter: 500 * time.Millisecond}); got != defaultRetryAfterSeconds {
		t.Fatalf("sub-second backoff falls back to default = %d", got)
	}
	if got := retryAfterSeconds(sdktransport.HTTPError{RetryAfter: time.Second}); got != 1 {
		t.Fatalf("one-second backoff = %d", got)
	}
}

func TestSourceErrorRoundTrip(t *testing.T) {
	t.Parallel()
	inner := errors.New("root")
	se := sourceFailure{err: inner, class: errorClassRetryable, terminal: false}
	if se.Error() != "root" || errors.Unwrap(se) != inner {
		t.Fatalf("unwrap = %v", se)
	}
	if se.FailureClass() != errorClassRetryable || se.TerminalFailure() {
		t.Fatalf("flags = %+v", se)
	}
	if want := "bad"; (configValidationError{err: errors.New(want)}).Error() != want {
		t.Fatal("config error text mismatch")
	}
}
