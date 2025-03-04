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
	go vet .
	staticcheck
	golangci-lint run
	make -C cmd/$(PROJECT) check
