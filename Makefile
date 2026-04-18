# Makefile — certchain build

BINARY_CERTD  = bin/certd
BINARY_CERTCTL = bin/certctl

.PHONY: all build test bdd clean

all: build test

build: $(BINARY_CERTD) $(BINARY_CERTCTL)

$(BINARY_CERTD):
	@mkdir -p bin
	go build -o $(BINARY_CERTD) ./cmd/certd

$(BINARY_CERTCTL):
	@mkdir -p bin
	go build -o $(BINARY_CERTCTL) ./cmd/certctl

test:
	go test ./internal/...

bdd: build
	cd features && go test -v -run TestFeatures

clean:
	rm -rf bin/
