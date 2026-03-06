VERSION ?= develop
GOARCH ?= $(shell go env GOARCH)

# Common directories
bin_dir := bin

# Common build flags
LDFLAGS := -w -s -X main.Version=$(VERSION)

ifdef CI_VERSION
VERSION := $(CI_VERSION)
endif

# Define color codes
GREEN := \033[32m
RED := \033[31m
RESET := \033[0m

.PHONY: all build ci install-tools vet fmt fmt-check generate generate-proto test test-bpf test-ci tidy clean

.DEFAULT_GOAL := build

# Define function to check for required tools
define check_tool
	@if ! command -v $(1) >/dev/null 2>&1; then \
		printf "${RED}$(1) not found${RESET}\n"; \
		printf "${RED}To install required tools, run: make install-tools${RESET}\n"; \
		exit 1; \
	fi
endef

all: fmt vet test build
ci: install-tools fmt-check vet build test-ci

install-tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install -v github.com/incu6us/goimports-reviser/v3@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/vektra/mockery/v2@v2.53.3
	@printf "${GREEN}Ensure tools directory is on PATH - default: $${HOME}/go/bin${RESET}\n"

$(bin_dir):
	mkdir -p $@

build: | $(bin_dir)
	@printf "${GREEN}Building cargowall...${RESET}\n"
	@GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="$(LDFLAGS)" \
		-o "$(bin_dir)/cargowall" "./cargowall.go" || \
		(printf "${RED}Build failed for cargowall${RESET}\n" && exit 1)

generate:
	@printf "${GREEN}Running go generate...${RESET}\n"
	go generate ./...
	@printf "${GREEN}Running mockery...${RESET}\n"
	mockery --config=./.mockery.yaml

generate-proto:
	@printf "${GREEN}Running buf generate in proto/...${RESET}\n"
	cd proto && npx buf generate

test:
	@printf "${GREEN}Running tests...${RESET}\n"
	go test ./...

test-bpf:
	@printf "${GREEN}Running BPF tests (requires root)...${RESET}\n"
	sudo go test -v -count=1 ./bpf/

test-ci:
	@printf "${GREEN}Running CI tests...${RESET}\n"
	go run gotest.tools/gotestsum@latest --junitfile test-results.xml --format testdox -- ./...
	@printf "${GREEN}Running BPF tests with sudo...${RESET}\n"
	sudo go run gotest.tools/gotestsum@latest --junitfile test-results-bpf.xml --format testdox -- -count=1 ./bpf/

vet:
	$(call check_tool,staticcheck)
	@printf "${GREEN}Running staticcheck...${RESET}\n"
	staticcheck ./...

fmt:
	$(call check_tool,goimports-reviser)
	@printf "${GREEN}Running goimports-reviser...${RESET}\n"
	goimports-reviser -rm-unused -set-alias -format ./...
	$(call check_tool,gofumpt)
	@printf "${GREEN}Running gofumpt...${RESET}\n"
	gofumpt -w .

fmt-check:
	$(call check_tool,goimports-reviser)
	@printf "${GREEN}Checking formatting with goimports-reviser...${RESET}\n"
	@if [ -n "$$(goimports-reviser -rm-unused -set-alias -format -set-exit-status -list-diff -output write ./...)" ]; then \
		printf "${RED}goimports-reviser found formatting issues${RESET}\n"; \
		exit 1; \
	fi
	$(call check_tool,gofumpt)
	@printf "${GREEN}Checking formatting with gofumpt...${RESET}\n"
	@if [ -n "$$(gofumpt -l .)" ]; then \
		printf "${RED}gofumpt found formatting issues${RESET}\n"; \
		exit 1; \
	fi

tidy:
	@printf "${GREEN}Running go mod tidy...${RESET}\n"
	go mod tidy

clean:
	@printf "${GREEN}Cleaning build artifacts...${RESET}\n"
	rm -rf $(bin_dir)

.NOTPARALLEL: test test-ci
