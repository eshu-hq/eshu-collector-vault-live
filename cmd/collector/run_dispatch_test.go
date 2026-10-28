// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

// TestRunDispatchErrors proves the entrypoint dispatch rejects bad arguments
// before any claim or seed work starts.
func TestRunDispatchErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if err := run(ctx, []string{"unexpected"}, nil, io.Discard, io.Discard, nil); err == nil ||
		!strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("claim err = %v", err)
	}
	if err := run(ctx, []string{"seed", "--bogus"}, nil, io.Discard, io.Discard, nil); err == nil ||
		!strings.Contains(err.Error(), "seed:") {
		t.Fatalf("seed flag err = %v", err)
	}
	if err := run(ctx, []string{"seed", "extra"}, nil, io.Discard, io.Discard, nil); err == nil ||
		!strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("seed positional err = %v", err)
	}
	if err := run(ctx, []string{"--bogus"}, nil, io.Discard, io.Discard, nil); err == nil {
		t.Fatalf("claim flag err = %v", err)
	}
}
