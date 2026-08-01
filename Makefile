GORELEASER_VERSION := v2.12.7
GOVULNCHECK_VERSION := v1.6.0
SYFT_VERSION := v1.40.0
CONTAINER_RUNTIME ?= podman

.PHONY: fmt-check notices-check test race vet verify build cross-compile vulncheck acceptance release-snapshot release-archive-verify container-build clean

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './dist/*'))"

notices-check:
	@tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	sh scripts/generate-third-party-notices.sh "$$tmp"; \
	cmp -s THIRD_PARTY_NOTICES "$$tmp" || { \
		echo "THIRD_PARTY_NOTICES is stale; run scripts/generate-third-party-notices.sh" >&2; \
		exit 1; \
	}

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

verify: fmt-check notices-check
	go mod tidy -diff
	go vet ./...
	go test -race ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/agentbusd ./cmd/agentbusd
	CGO_ENABLED=0 go build -trimpath -o bin/agentbus ./cmd/agentbus
	CGO_ENABLED=0 go build -trimpath -o bin/agentbus-mcp-bridge ./cmd/agentbus-mcp-bridge

cross-compile:
	@set -eu; \
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		out="dist/agentbus_$${os}_$${arch}"; \
		mkdir -p "$$out"; \
		echo "==> $$os/$$arch"; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -o "$$out/agentbusd" ./cmd/agentbusd; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -o "$$out/agentbus" ./cmd/agentbus; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -o "$$out/agentbus-mcp-bridge" ./cmd/agentbus-mcp-bridge; \
	done

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

acceptance:
	sh scripts/local-acceptance.sh

release-snapshot: .tools/syft
	PATH="$(CURDIR)/.tools:$$PATH" go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --snapshot --clean
	sh scripts/verify-release-archive.sh dist

release-archive-verify:
	sh scripts/verify-release-archive.sh dist

.tools/syft:
	mkdir -p .tools
	GOBIN="$(CURDIR)/.tools" go install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)

container-build:
	$(CONTAINER_RUNTIME) build -f Containerfile -t localhost/agentbus:dev .

clean:
	rm -rf bin dist
