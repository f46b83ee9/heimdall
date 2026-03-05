.PHONY: all build test clean run docker lint

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=heimdall
VERSION ?= $(shell git describe --tags --always --dirty || echo "dev")

# Build flags
LDFLAGS=-ldflags "-X github.com/f46b83ee9/heimdall/cmd.Version=$(VERSION)"

all: test build

build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v .

test:
	$(GOTEST) -v -race -cover ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

run: build
	./$(BINARY_NAME) serve --config config.yaml

docker:
	docker build --build-arg VERSION=$(VERSION) -t heimdall-proxy:$(VERSION) -t heimdall-proxy:latest -f Dockerfile .

tidy:
	$(GOMOD) tidy
	$(GOMOD) verify
