BINARY  := gofuzz-evm
MAIN    := ./cmd/gofuzz-evm
VERSION := 0.1.0
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

.PHONY: all build test lint clean docker

all: build

build:
	go build $(LDFLAGS) -o $(BINARY) $(MAIN)

test:
	go test ./...

test-verbose:
	go test -v ./...

bench:
	go test -bench=. -benchmem ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	rm -rf output/ corpus/

docker:
	docker build -t gofuzz-evm:$(VERSION) .

.PHONY: fuzz-abi
fuzz-abi:
	go test -fuzz=FuzzParseABI ./internal/abi/ -fuzztime=60s
