.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/jameshoulder/dnsdaddy/internal/version.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1;32m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary for this machine
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/dnsdaddy ./cmd/dnsdaddy

.PHONY: build-lab
build-lab: ## Build the lab traffic generator and synthetic responder
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/dnsdaddy-lab ./cmd/dnsdaddy-lab

.PHONY: lab
lab: ## Start the isolated demo lab in Docker (dashboard on :8081)
	docker compose --profile lab up --build -d
	@echo
	@echo "  Lab running. Dashboard:  http://127.0.0.1:8081"
	@echo "  Password:                dnsdaddy-lab-demo-password"
	@echo "  Findings appear after about a minute; see labs/README.md"

.PHONY: lab-down
lab-down: ## Stop the lab and delete its data (does not touch a production deployment)
	docker compose --profile lab down -v

.PHONY: run
run: ## Run locally on high ports with data in ./tmp (no root needed)
	@mkdir -p tmp
	DNSDADDY_DATA_DIR=./tmp \
	DNSDADDY_DNS_LISTEN_UDP=127.0.0.1:5353 \
	DNSDADDY_DNS_LISTEN_TCP=127.0.0.1:5353 \
	DNSDADDY_HTTP_LISTEN=127.0.0.1:8080 \
	go run ./cmd/dnsdaddy -config ./dnsdaddy.example.yaml -log-level debug

.PHONY: test
test: ## Run the test suite
	go test ./...

.PHONY: test-race
test-race: ## Run tests with the race detector
	go test -race ./...

.PHONY: test-ui
test-ui: ## Run the dashboard's JavaScript tests (needs node; no packages to install)
	node --test internal/web/app.test.js

.PHONY: test-daddybound
test-daddybound: ## Compare Daddybound against libunbound and BIND delv (needs libunbound-dev, bind9-dnsutils, cgo)
	CGO_ENABLED=1 go test -tags daddybound_unbound -v ./internal/daddybound/...

.PHONY: corpus
corpus: ## Compare Daddybound against libunbound and delv over real Internet names (needs network, several minutes)
	@# Deliberately not part of `make test` and not in CI. It needs the
	@# network, a public recursive resolver, both reference validators and
	@# several minutes, and its result depends on the state of zones nobody
	@# here controls — every one of which is a reason it must not gate a pull
	@# request. A CI job that goes red because someone else let a signature
	@# expire teaches contributors to re-run red builds.
	DADDYBOUND_CORPUS=1 CGO_ENABLED=1 go test -tags daddybound_unbound \
		./internal/daddybound/differential/ -run TestRealWorldCorpus -v -count=1 -timeout 60m

.PHONY: fuzz-daddybound
fuzz-daddybound: ## Fuzz the Daddybound input surface for 30s per target
	@# Discovered rather than listed, for the reason the CI step gives: a
	@# hard-coded list stops covering whatever was added last, which is how
	@# fuzzing dies quietly. Package and target together, because -fuzz
	@# refuses a pattern matching more than one package.
	@grep -rn '^func Fuzz[A-Za-z0-9_]*(' ./internal/daddybound/ | \
	while IFS= read -r line; do \
		file=$${line%%:*}; fn=$${line##*func }; \
		printf '%s %s\n' "$$(dirname "$$file")" "$${fn%%(*}"; \
	done | sort -u | while read -r pkg target; do \
		echo "--- $$pkg $$target ---"; \
		go test "$$pkg" -run '^$$' -fuzz "^$$target$$" -fuzztime=30s || exit 1; \
	done

.PHONY: cover
cover: ## Run tests and open a coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	@echo "HTML report: go tool cover -html=coverage.out"

.PHONY: bench
bench: ## Run benchmarks for the DNS hot path
	go test -bench=. -benchmem -run='^$$' ./internal/blocklist/... ./internal/policy/... ./internal/domainutil/... ./internal/clientacl/...

.PHONY: lint
lint: ## Vet and check formatting
	go vet ./...
	@unformatted=$$(gofmt -l ./cmd ./internal); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

.PHONY: fmt
fmt: ## Format the code
	gofmt -w ./cmd ./internal

.PHONY: release
release: ## Cross-compile release archives into dist/
	@rm -rf dist && mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name=dnsdaddy_$(VERSION:v%=%)_$${os}_$${arch}; \
		echo "  building $$name"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags="$(LDFLAGS)" -o dist/dnsdaddy ./cmd/dnsdaddy || exit 1; \
		tar -czf dist/$$name.tar.gz -C dist dnsdaddy; \
		rm dist/dnsdaddy; \
	done
	@cd dist && sha256sum *.tar.gz > checksums.txt
	@echo "Wrote dist/ ($(VERSION))"

.PHONY: docker
docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t dnsdaddy:$(VERSION) -t dnsdaddy:latest .

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf bin dist tmp coverage.out
