# Makefile — certchain build

BINARY_CERTD            = bin/certd
BINARY_CERTCTL          = bin/certctl
BINARY_CERTCHAIN_ISSUER = bin/certchain-issuer
BINARY_CERTCHAIN_SYNC   = bin/certchain-sync
BINARY_ANNOTATION_CTRL  = bin/annotation-ctrl

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
STATICCHECK   ?= staticcheck

.PHONY: all build test bdd lint vet fmt staticcheck tidy verify audit vuln licenses clean

all: build test

build: $(BINARY_CERTD) $(BINARY_CERTCTL) $(BINARY_CERTCHAIN_ISSUER) $(BINARY_CERTCHAIN_SYNC) $(BINARY_ANNOTATION_CTRL)

$(BINARY_CERTD):
	@mkdir -p bin
	$(GO) build -o $(BINARY_CERTD) ./cmd/certd

$(BINARY_CERTCTL):
	@mkdir -p bin
	$(GO) build -o $(BINARY_CERTCTL) ./cmd/certctl

$(BINARY_CERTCHAIN_ISSUER):
	@mkdir -p bin
	$(GO) build -o $(BINARY_CERTCHAIN_ISSUER) ./cmd/certchain-issuer

$(BINARY_CERTCHAIN_SYNC):
	@mkdir -p bin
	$(GO) build -o $(BINARY_CERTCHAIN_SYNC) ./cmd/certchain-sync

$(BINARY_ANNOTATION_CTRL):
	@mkdir -p bin
	$(GO) build -o $(BINARY_ANNOTATION_CTRL) ./cmd/annotation-ctrl

test:
	$(GO) test -race -count=1 ./...

bdd: build
	cd features && $(GO) test -v -run TestFeatures

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

lint:
	$(GOLANGCI_LINT) run --timeout=5m

staticcheck:
	$(STATICCHECK) ./...

tidy:
	$(GO) mod tidy

# verify runs the full gate used in CI. Fails fast on the first problem.
verify: fmt vet lint staticcheck audit test

# audit is the dependency-hygiene gate for CM-28. It is intentionally
# composed of existing checks (vet, tidy-diff, staticcheck) plus govulncheck
# so that a single target answers "are our deps clean right now?"
#
# `go mod tidy -diff` prints the exact go.mod/go.sum changes tidy would make
# and exits non-zero if any are needed, which catches drift between committed
# manifests and the import graph.
audit:
	$(GO) vet ./...
	$(GO) mod tidy -diff
	$(STATICCHECK) ./...
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# vuln is a narrower alias for "just the CVE scan" so developers can rerun
# the slow part of audit in isolation after bumping a dependency.
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# licenses produces a CSV inventory of every module in the build graph.
# `go-licenses report` classifies each module's LICENSE file against the
# SPDX identifier set so copyleft/unknown licenses are visible at review
# time. We also keep a raw `go list -m all` snapshot as a fallback for
# modules go-licenses cannot classify (vendored, replaced, etc.).
licenses:
	@mkdir -p bin
	$(GO) list -m all > bin/modules.txt
	$(GO) run github.com/google/go-licenses@latest report ./... > bin/licenses.csv
	@echo "wrote bin/modules.txt and bin/licenses.csv"

clean:
	rm -rf bin/
