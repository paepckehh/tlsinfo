PROJECT=$(shell basename $(CURDIR))

all:
	make -C cmd/$(PROJECT) all

examples:
	make -C cmd/$(PROJECT) examples

deps: 
	rm go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v	

check: 
	gofmt -w -s .
	CGO_ENABLED=0 go vet .
	CGO_ENABLED=0 staticcheck
	CGO_ENABLED=0 golangci-lint run
	make -C cmd/$(PROJECT) check
