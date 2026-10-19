VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
LDFLAGS=-s -w -X main._version=$(VERSION)

all: build
	./tlsinfo github.com

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o tlsinfo .

version:
	@echo $(VERSION)

check:
	gofmt -w -s .
	CGO_ENABLED=0 go vet .
	CGO_ENABLED=0 go fix -diff .
	CGO_ENABLED=0 go fix .
	CGO_ENABLED=0 golangci-lint run
	# CGO_ENABLED=0 staticcheck

examples: build
	./tlsinfo github.com
	./tlsinfo paepcke.de
