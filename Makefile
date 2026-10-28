# Local parity for CI: `make ci` runs the lint, test, and race lane
# commands from .github/workflows/ci.yml. That target is the whole local
# contract. golangci-lint is the one external binary (v2.12.2, the version
# Eshu uses); see CONTRIBUTING.md for the one-time install.

.PHONY: ci lint test race

ci: lint test race

lint:
	go vet ./...
	golangci-lint run ./...
	golangci-lint fmt --diff ./...
	go mod tidy -diff
	git diff --exit-code -- go.mod go.sum
	! rg -n '^replace ' go.mod
	over=`find . -name '*.go' -not -path './vendor/*' -not -path './.git/*' -exec wc -l {} + | awk '$$1 > 500 && $$2 != "total" {print}'`; \
	if [ -n "$$over" ]; then echo "$$over"; echo "FAIL: .go files over 500 lines"; exit 1; fi

test:
	go build ./...
	go test ./... -count=1

# The floor lives in ci.yml (COVERAGE_FLOOR) and may only rise; the Makefile
# reads it so the two can never desync.
race:
	go test ./... -race -count=1 -covermode=atomic -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -n 30
	total=`go tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/, "", $$3); print $$3}'`; \
	floor=`awk '/COVERAGE_FLOOR:/ {gsub(/"/, "", $$2); print $$2}' .github/workflows/ci.yml`; \
	echo "total=$$total floor=$$floor"; \
	awk -v t="$$total" -v f="$$floor" 'BEGIN { if (t + 0 < f + 0) { print "FAIL: coverage below floor"; exit 1 } }'
