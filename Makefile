# Makefile — certchain build

BINARY_CERTD            = bin/certd
BINARY_CERTCTL          = bin/certctl
BINARY_CERTCHAIN_ISSUER = bin/certchain-issuer
BINARY_CERTCHAIN_SYNC   = bin/certchain-sync

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
STATICCHECK   ?= staticcheck

.PHONY: all build test bdd lint vet fmt staticcheck tidy verify clean

all: build test

build: $(BINARY_CERTD) $(BINARY_CERTCTL) $(BINARY_CERTCHAIN_ISSUER) $(BINARY_CERTCHAIN_SYNC)

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
verify: fmt vet lint staticcheck test

clean:
	rm -rf bin/
