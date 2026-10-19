PROJECT=$(shell basename $(CURDIR))
VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)

all:
	make -C cmd/$(PROJECT) all

build:
	CGO_ENABLED=0 go build -ldflags "-s -w -X main._version=$(VERSION)" -o tlsinfo ./cmd/$(PROJECT)

version:
	@echo $(VERSION)

examples:
	make -C cmd/$(PROJECT) examples

deps: 
	rm go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v	

test:
	CGO_ENABLED=0 go test ./...

check:
	gofmt -w -s .
	CGO_ENABLED=0 go vet .
	CGO_ENABLED=0 go fix -diff .
	CGO_ENABLED=0 go fix .
	CGO_ENABLED=0 golangci-lint run
	# CGO_ENABLED=0 staticcheck
	make -C cmd/$(PROJECT) check
