BINARY = loupe
CONFIG ?= config.yaml
GO     = PATH=$(PATH):/usr/local/go/bin go  # go from PATH, else /usr/local/go

build:
	$(GO) build -o $(BINARY) ./cmd/loupe/

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

run: build
	./$(BINARY) $(CONFIG)

# make release VERSION=0.1.0
release:
	PATH=$(PATH):/usr/local/go/bin scripts/release.sh $(VERSION)

.PHONY: build test vet run release
